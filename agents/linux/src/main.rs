use std::{
    env,
    io::{self, Write},
    process::ExitCode,
};

use secmon_agent::collect_default;

const MAX_STDOUT_BYTES: usize = security_monitor_agent_protocol::MAX_DOCUMENT_BYTES;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            let _ = writeln!(io::stderr(), "secmon-agent: {code}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), &'static str> {
    let mut args = env::args_os();
    let _binary = args.next();
    if args.next().as_deref() != Some(std::ffi::OsStr::new("collect")) || args.next().is_some() {
        return Err("unsupported operation");
    }
    if let Some(original) = env::var_os("SSH_ORIGINAL_COMMAND")
        && !matches_original(&original)
    {
        return Err("unsupported operation");
    }

    let result = collect_default().await;
    result
        .inventory
        .validate()
        .map_err(|_| "collection failed")?;
    let bytes = serde_json::to_vec(&result.inventory).map_err(|_| "collection failed")?;
    if bytes.len() > MAX_STDOUT_BYTES {
        return Err("collection output exceeded the limit");
    }
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&bytes)
        .map_err(|_| "collection output failed")?;
    stdout
        .write_all(b"\n")
        .map_err(|_| "collection output failed")?;
    stdout.flush().map_err(|_| "collection output failed")?;
    Ok(())
}

fn matches_original(value: &std::ffi::OsStr) -> bool {
    value == "secmon-agent collect"
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    #[test]
    fn forced_command_original_must_be_exact() {
        assert!(super::matches_original(OsStr::new("secmon-agent collect")));
        assert!(!super::matches_original(OsStr::new("id")));
        assert!(!super::matches_original(OsStr::new(
            "secmon-agent collect; id"
        )));
    }
}
