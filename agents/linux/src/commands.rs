use std::{ffi::OsString, fs, process::Stdio, time::Duration};

use thiserror::Error;
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_COMMAND_OUTPUT: usize = 8 * 1024 * 1024;
const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const OCI_LABEL_TEMPLATE: &str = "{{.Id}}\\t{{.Name}}\\t{{.Config.Image}}\\t{{.Image}}\\t{{index .Config.Labels \"org.opencontainers.image.revision\"}}\\t{{index .Config.Labels \"org.opencontainers.image.version\"}}\\t{{index .Config.Labels \"org.opencontainers.image.source\"}}";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeExecutable {
    NodeUsrBin,
    NodeUsrLocal,
    NodeBin,
    PhpUsrBin,
    PhpUsrLocal,
    PythonUsrBin,
    PythonUsrLocal,
    Python3UsrBin,
    Python3UsrLocal,
}

impl RuntimeExecutable {
    pub fn all() -> &'static [Self] {
        &[
            Self::NodeUsrBin,
            Self::NodeUsrLocal,
            Self::NodeBin,
            Self::PhpUsrBin,
            Self::PhpUsrLocal,
            Self::PythonUsrBin,
            Self::PythonUsrLocal,
            Self::Python3UsrBin,
            Self::Python3UsrLocal,
        ]
    }

    pub(crate) fn program(self) -> &'static str {
        match self {
            Self::NodeUsrBin => "/usr/bin/node",
            Self::NodeUsrLocal => "/usr/local/bin/node",
            Self::NodeBin => "/bin/node",
            Self::PhpUsrBin => "/usr/bin/php",
            Self::PhpUsrLocal => "/usr/local/bin/php",
            Self::PythonUsrBin => "/usr/bin/python",
            Self::PythonUsrLocal => "/usr/local/bin/python",
            Self::Python3UsrBin => "/usr/bin/python3",
            Self::Python3UsrLocal => "/usr/local/bin/python3",
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::NodeUsrBin | Self::NodeUsrLocal | Self::NodeBin => "node",
            Self::PhpUsrBin | Self::PhpUsrLocal => "php",
            Self::PythonUsrBin | Self::PythonUsrLocal => "python",
            Self::Python3UsrBin | Self::Python3UsrLocal => "python3",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostCommand {
    DpkgPackages,
    RpmPackages,
    ApkPackages,
    RuntimeVersion(RuntimeExecutable),
    #[cfg(target_os = "linux")]
    SystemdServices,
    DockerList,
    DockerInspect {
        container_id: String,
    },
}

impl HostCommand {
    pub fn label(&self) -> &'static str {
        match self {
            Self::DpkgPackages => "dpkg-query",
            Self::RpmPackages => "rpm",
            Self::ApkPackages => "apk",
            Self::RuntimeVersion(runtime) => runtime.name(),
            #[cfg(target_os = "linux")]
            Self::SystemdServices => "systemctl",
            Self::DockerList => "docker-ps",
            Self::DockerInspect { .. } => "docker-inspect",
        }
    }

    fn executable_and_args(&self) -> Result<(&'static str, Vec<OsString>), HostCommandError> {
        let (program, args): (&'static str, &[&str]) = match self {
            Self::DpkgPackages => (
                "/usr/bin/dpkg-query",
                &[
                    "-W",
                    "-f=${binary:Package}\\t${Version}\\t${Architecture}\\t${Status}\\n",
                ],
            ),
            Self::RpmPackages => (
                "/usr/bin/rpm",
                &[
                    "-qa",
                    "--qf",
                    "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n",
                ],
            ),
            Self::ApkPackages => ("/sbin/apk", &["info", "-v"]),
            Self::RuntimeVersion(runtime) => (runtime.program(), &["--version"]),
            #[cfg(target_os = "linux")]
            Self::SystemdServices => (
                "/usr/bin/systemctl",
                &[
                    "list-units",
                    "--type=service",
                    "--state=running",
                    "--no-legend",
                    "--no-pager",
                ],
            ),
            Self::DockerList => (
                "/usr/bin/docker",
                &["ps", "--no-trunc", "--format", "{{json .}}"],
            ),
            Self::DockerInspect { container_id } => {
                if !(12..=64).contains(&container_id.len())
                    || !container_id.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(HostCommandError::InvalidArgument);
                }
                let args = vec![
                    OsString::from("inspect"),
                    OsString::from("--type=container"),
                    OsString::from("--format"),
                    OsString::from(OCI_LABEL_TEMPLATE),
                    OsString::from(container_id),
                ];
                return Ok(("/usr/bin/docker", args));
            }
        };
        Ok((program, args.iter().map(OsString::from).collect()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HostCommandError {
    #[error("allowlisted command is unavailable")]
    Unavailable,
    #[error("allowlisted command failed")]
    Failed,
    #[error("allowlisted command exceeded its time limit")]
    Timeout,
    #[error("allowlisted command output exceeded its size limit")]
    OutputTooLarge,
    #[error("allowlisted command argument is invalid")]
    InvalidArgument,
}

#[derive(Debug)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
}

pub async fn run_allowlisted(command: &HostCommand) -> Result<CommandOutput, HostCommandError> {
    let (program, args) = command.executable_and_args()?;
    match fs::metadata(program) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err(HostCommandError::Unavailable),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(HostCommandError::Unavailable);
        }
        Err(_) => return Err(HostCommandError::Failed),
    }
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => HostCommandError::Unavailable,
            _ => HostCommandError::Failed,
        })?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill().await;
        return Err(HostCommandError::Failed);
    };
    let read_stdout = async move {
        let mut limited = stdout.take((MAX_COMMAND_OUTPUT + 1) as u64);
        let mut output = Vec::new();
        limited
            .read_to_end(&mut output)
            .await
            .map_err(|_| HostCommandError::Failed)?;
        Ok::<_, HostCommandError>(output)
    };
    let output = timeout(COMMAND_TIMEOUT, read_stdout)
        .await
        .map_err(|_| HostCommandError::Timeout)??;
    if output.len() > MAX_COMMAND_OUTPUT {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(HostCommandError::OutputTooLarge);
    }
    let status = timeout(COMMAND_TIMEOUT, child.wait())
        .await
        .map_err(|_| HostCommandError::Timeout)?
        .map_err(|_| HostCommandError::Failed)?;
    if !status.success() {
        return Err(HostCommandError::Failed);
    }
    tracing::debug!(
        command = command.label(),
        output_bytes = output.len(),
        "allowlisted host command completed"
    );
    Ok(CommandOutput { stdout: output })
}

#[cfg(test)]
mod tests {
    use super::{HostCommand, RuntimeExecutable};

    #[test]
    fn allowlist_has_fixed_program_and_argument_vectors() {
        for command in [
            HostCommand::DpkgPackages,
            HostCommand::RpmPackages,
            HostCommand::ApkPackages,
            HostCommand::RuntimeVersion(RuntimeExecutable::NodeUsrBin),
            #[cfg(target_os = "linux")]
            HostCommand::SystemdServices,
            HostCommand::DockerList,
        ] {
            let (program, args) = command
                .executable_and_args()
                .expect("fixed command is valid");
            assert!(program.starts_with('/'));
            assert!(
                !args
                    .iter()
                    .any(|argument| argument.to_string_lossy().contains("$(`"))
            );
            if command == HostCommand::DpkgPackages {
                assert!(args[1].to_string_lossy().contains("${Status}"));
            }
        }
        assert!(
            HostCommand::DockerInspect {
                container_id: "bad;id".to_owned()
            }
            .executable_and_args()
            .is_err()
        );
        assert!(
            HostCommand::DockerInspect {
                container_id: "a".repeat(64)
            }
            .executable_and_args()
            .is_ok()
        );
    }
}
