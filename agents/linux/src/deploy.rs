use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;

use chrono::{DateTime, Utc};
use security_monitor_agent_protocol::{DeploymentIdentity, DeploymentSource};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::processes::ProcessSnapshot;

const MAX_DEPLOYMENT_FILE_BYTES: u64 = 64 * 1024;
const MAX_ENV_BYTES: u64 = 1024 * 1024;
const MAX_GIT_REFS_BYTES: u64 = 16 * 1024 * 1024;
const SYSTEM_DEPLOYMENTS: &str = "/etc/secmon/deployments.d";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentFile {
    commit_sha: Option<String>,
    repo: Option<String>,
    release_id: Option<String>,
    image_digest: Option<String>,
    built_at: Option<DateTime<Utc>>,
}

pub fn collect_deployments(snapshot: &mut ProcessSnapshot, allowed_roots: &[PathBuf]) -> bool {
    let mut any_unknown = false;
    for service in &mut snapshot.services {
        if service.container_id.is_some() {
            if service
                .deploy_identity
                .as_ref()
                .is_none_or(|identity| identity.source == DeploymentSource::Unknown)
            {
                any_unknown = true;
                service.deploy_identity = Some(unknown_identity());
            }
            continue;
        }
        let process = service
            .pid
            .and_then(|pid| snapshot.processes.iter().find(|process| process.pid == pid));
        let app_directory = process
            .map(|process| process.pid)
            .and_then(process_working_directory)
            .filter(|directory| allowed_roots.iter().any(|root| directory.starts_with(root)));
        let deployment = app_directory
            .as_deref()
            .and_then(read_application_deployment)
            .or_else(|| read_system_deployment(&service.name))
            .or_else(|| {
                process
                    .map(|process| process.pid)
                    .and_then(read_deployment_environment)
            })
            .or_else(|| app_directory.as_deref().and_then(read_git_head));
        if deployment.is_none() {
            any_unknown = true;
        }
        service.deploy_identity = Some(deployment.unwrap_or_else(unknown_identity));
    }
    any_unknown
}

pub fn unknown_identity() -> DeploymentIdentity {
    DeploymentIdentity {
        commit_sha: None,
        repository: None,
        release_id: None,
        image_digest: None,
        built_at: None,
        source: DeploymentSource::Unknown,
        integrity_verified: false,
    }
}

fn process_working_directory(pid: u32) -> Option<PathBuf> {
    let path = fs::read_link(format!("/proc/{pid}/cwd")).ok()?;
    path.canonicalize().ok()
}

fn read_application_deployment(app_directory: &Path) -> Option<DeploymentIdentity> {
    let allowed_root = app_directory.canonicalize().ok()?;
    let path = app_directory.join(".secmon-deploy.json");
    read_deployment_file(&path, &allowed_root, DeploymentSource::ApplicationFile)
}

fn read_system_deployment(service_name: &str) -> Option<DeploymentIdentity> {
    if service_name.is_empty()
        || service_name.len() > 200
        || !service_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-@".contains(&byte))
    {
        return None;
    }
    let root = Path::new(SYSTEM_DEPLOYMENTS).canonicalize().ok()?;
    let file_name = format!("{service_name}.json");
    read_deployment_file(&root.join(file_name), &root, DeploymentSource::SystemFile)
}

fn read_deployment_file(
    path: &Path,
    allowed_root: &Path,
    source: DeploymentSource,
) -> Option<DeploymentIdentity> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_DEPLOYMENT_FILE_BYTES
    {
        return None;
    }
    let canonical = path.canonicalize().ok()?;
    if !canonical.starts_with(allowed_root) {
        return None;
    }
    let data = read_bounded_file(&canonical, MAX_DEPLOYMENT_FILE_BYTES)?;
    let record: DeploymentFile = serde_json::from_slice(&data).ok()?;
    normalize_deployment(record, source)
}

fn normalize_deployment(
    record: DeploymentFile,
    source: DeploymentSource,
) -> Option<DeploymentIdentity> {
    let commit_sha = match record.commit_sha.as_deref() {
        Some(value) => Some(normalize_commit(value)?),
        None => None,
    };
    let repository = match record.repo.as_deref() {
        Some(value) => Some(validate_repository(value)?),
        None => None,
    };
    let release_id = match record.release_id.as_deref() {
        Some(value) => Some(validate_short_text(value)?),
        None => None,
    };
    let image_digest = match record.image_digest.as_deref() {
        Some(value) => Some(validate_digest(value)?),
        None => None,
    };
    if commit_sha.is_none()
        && repository.is_none()
        && release_id.is_none()
        && image_digest.is_none()
    {
        return None;
    }
    Some(DeploymentIdentity {
        commit_sha,
        repository,
        release_id,
        image_digest,
        built_at: record.built_at,
        source,
        integrity_verified: false,
    })
}

fn read_deployment_environment(pid: u32) -> Option<DeploymentIdentity> {
    let data = read_bounded_file(
        &PathBuf::from(format!("/proc/{pid}/environ")),
        MAX_ENV_BYTES,
    )?;
    let commit = data
        .split(|byte| *byte == 0)
        .filter_map(|entry| {
            let separator = entry.iter().position(|byte| *byte == b'=')?;
            Some((&entry[..separator], &entry[separator + 1..]))
        })
        .find_map(|(name, value)| {
            matches!(
                name,
                b"SECMON_COMMIT_SHA" | b"SOURCE_COMMIT" | b"GIT_COMMIT"
            )
            .then(|| std::str::from_utf8(value).ok().and_then(normalize_commit))
            .flatten()
        });
    commit.map(|commit_sha| DeploymentIdentity {
        commit_sha: Some(commit_sha),
        repository: None,
        release_id: None,
        image_digest: None,
        built_at: None,
        source: DeploymentSource::ServiceEnvironment,
        integrity_verified: false,
    })
}

fn read_git_head(app_directory: &Path) -> Option<DeploymentIdentity> {
    let git_directory = app_directory.join(".git").canonicalize().ok()?;
    if !git_directory.starts_with(app_directory) || !git_directory.is_dir() {
        return None;
    }
    let head_path = git_directory.join("HEAD");
    let head = String::from_utf8(read_bounded_file(&head_path, 4096)?.to_vec()).ok()?;
    let commit = if let Some(reference) = head.trim().strip_prefix("ref: ") {
        if reference.contains("..")
            || reference.starts_with('/')
            || reference.contains('\\')
            || reference.bytes().any(|byte| byte.is_ascii_control())
        {
            return None;
        }
        let ref_path = git_directory.join(reference);
        match ref_path.canonicalize() {
            Ok(canonical_ref) if canonical_ref.starts_with(&git_directory) => {
                String::from_utf8(read_bounded_file(&canonical_ref, 4096)?.to_vec())
                    .ok()?
                    .trim()
                    .to_owned()
            }
            _ => read_packed_ref(&git_directory, reference)?,
        }
    } else {
        head.trim().to_owned()
    };
    let commit_sha = normalize_commit(&commit)?;
    Some(DeploymentIdentity {
        commit_sha: Some(commit_sha),
        repository: None,
        release_id: None,
        image_digest: None,
        built_at: None,
        source: DeploymentSource::GitHead,
        integrity_verified: false,
    })
}

fn read_packed_ref(git_directory: &Path, reference: &str) -> Option<String> {
    let packed_refs = read_bounded_file(&git_directory.join("packed-refs"), MAX_GIT_REFS_BYTES)?;
    std::str::from_utf8(&packed_refs)
        .ok()?
        .lines()
        .filter(|line| !line.starts_with('#') && !line.starts_with('^'))
        .find_map(|line| {
            let (commit, name) = line.split_once(' ')?;
            (name == reference).then(|| commit.to_owned())
        })
}

fn read_bounded_file(path: &Path, limit: u64) -> Option<Zeroizing<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(libc::O_NOFOLLOW);
    let file: File = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > limit {
        return None;
    }
    let mut data = Zeroizing::new(Vec::with_capacity(metadata.len().min(limit) as usize));
    file.take(limit.saturating_add(1))
        .read_to_end(&mut data)
        .ok()?;
    (data.len() as u64 <= limit).then_some(data)
}

fn normalize_commit(value: &str) -> Option<String> {
    if !(7..=64).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn validate_repository(value: &str) -> Option<String> {
    if value.len() > 2048
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return None;
    }
    let normalized = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let url = url::Url::parse(&normalized).ok()?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(url.to_string().trim_end_matches('/').to_owned())
}

fn validate_short_text(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 256 || value.bytes().any(|byte| byte.is_ascii_control()) {
        None
    } else {
        Some(value.to_owned())
    }
}

fn validate_digest(value: &str) -> Option<String> {
    let (algorithm, encoded) = value.split_once(':')?;
    if algorithm != "sha256"
        || encoded.len() != 64
        || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some(format!("sha256:{}", encoded.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::{
        DeploymentFile, DeploymentSource, normalize_commit, normalize_deployment,
        validate_repository,
    };

    #[test]
    fn deployment_values_are_validated_and_never_mark_integrity_verified() {
        let deployment = normalize_deployment(
            DeploymentFile {
                commit_sha: Some("ABCDEF0123456".to_owned()),
                repo: Some("github.com/acme/service".to_owned()),
                release_id: Some("v2.1.0".to_owned()),
                image_digest: None,
                built_at: None,
            },
            DeploymentSource::ApplicationFile,
        )
        .expect("deploy identity should normalize");
        assert_eq!(deployment.commit_sha.as_deref(), Some("abcdef0123456"));
        assert_eq!(
            deployment.repository.as_deref(),
            Some("https://github.com/acme/service")
        );
        assert!(!deployment.integrity_verified);
        assert!(normalize_commit("abc$(id)").is_none());
        assert!(validate_repository("https://user:secret@example.test/repo").is_none());
    }
}
