use super::*;

pub(super) struct RuntimeCollection {
    pub(super) records: Vec<RuntimeRecord>,
    pub(super) check: CollectionCheck,
}

pub(super) async fn collect_runtimes() -> RuntimeCollection {
    let mut records = Vec::new();
    let mut command_failures = 0usize;
    let mut invalid_outputs = 0usize;
    let mut successful_outputs = 0usize;
    for runtime in RuntimeExecutable::all() {
        match run_allowlisted(&HostCommand::RuntimeVersion(*runtime)).await {
            Ok(output) => {
                successful_outputs += 1;
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
            Err(_) => command_failures += 1,
        }
    }
    records.sort_by(|left, right| {
        (left.name.as_str(), left.binary_path.as_str())
            .cmp(&(right.name.as_str(), right.binary_path.as_str()))
    });
    records.dedup_by(|left, right| left.binary_path == right.binary_path);
    let status = if successful_outputs == 0 {
        CheckStatus::Unavailable
    } else if command_failures > 0 || invalid_outputs > 0 {
        CheckStatus::Partial
    } else {
        CheckStatus::Complete
    };
    RuntimeCollection {
        check: check(
            CheckKind::Runtimes,
            status,
            if command_failures > 0 {
                DiagnosticCode::CommandUnavailable
            } else {
                DiagnosticCode::InvalidOutput
            },
            records.len(),
        ),
        records,
    }
}
