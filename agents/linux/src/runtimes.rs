use super::*;
use crate::commands::HostCommandError;

pub(super) struct RuntimeCollection {
    pub(super) records: Vec<RuntimeRecord>,
    pub(super) check: CollectionCheck,
}

pub(super) async fn collect_runtimes() -> RuntimeCollection {
    let mut records = Vec::new();
    let mut command_failures = 0usize;
    let mut invalid_outputs = 0usize;
    let mut failure_diagnostic = DiagnosticCode::InvalidOutput;
    for runtime in RuntimeExecutable::all() {
        match run_allowlisted(&HostCommand::RuntimeVersion(*runtime)).await {
            Ok(output) => {
                let output_text = String::from_utf8_lossy(&output.stdout);
                let version = output_text
                    .lines()
                    .find(|line| line.chars().any(|character| character.is_ascii_digit()))
                    .map(str::trim)
                    .filter(|version| !version.is_empty());
                if let Some(version) = version {
                    records.push(RuntimeRecord {
                        name: runtime.name().to_owned(),
                        version: version.to_owned(),
                        binary_path: runtime.program().to_owned(),
                    });
                } else {
                    invalid_outputs += 1;
                }
            }
            Err(HostCommandError::Unavailable) => {}
            Err(error) => {
                command_failures += 1;
                failure_diagnostic = command_diagnostic(error);
            }
        }
    }
    records.sort_by(|left, right| {
        (left.name.as_str(), left.binary_path.as_str())
            .cmp(&(right.name.as_str(), right.binary_path.as_str()))
    });
    records.dedup_by(|left, right| left.binary_path == right.binary_path);
    let status = runtime_collection_status(command_failures, invalid_outputs);
    RuntimeCollection {
        check: check(
            CheckKind::Runtimes,
            status,
            failure_diagnostic,
            records.len(),
        ),
        records,
    }
}

fn runtime_collection_status(command_failures: usize, invalid_outputs: usize) -> CheckStatus {
    if command_failures > 0 || invalid_outputs > 0 {
        CheckStatus::Partial
    } else {
        CheckStatus::Complete
    }
}

#[cfg(test)]
mod tests {
    use security_monitor_agent_protocol::CheckStatus;

    #[test]
    fn absent_optional_runtimes_do_not_make_collection_partial() {
        assert_eq!(
            super::runtime_collection_status(0, 0),
            CheckStatus::Complete
        );
        assert_eq!(super::runtime_collection_status(1, 0), CheckStatus::Partial);
        assert_eq!(super::runtime_collection_status(0, 1), CheckStatus::Partial);
    }
}
