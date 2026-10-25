use super::*;
use crate::deploy::unknown_identity;

pub(super) async fn collect_containers(
    docker_cli_approved: bool,
) -> (
    Vec<ContainerRecord>,
    CollectionCheck,
    BTreeMap<String, DeploymentIdentity>,
) {
    if !docker_cli_approved {
        return (
            Vec::new(),
            check(
                CheckKind::Containers,
                CheckStatus::Unavailable,
                DiagnosticCode::ConfigurationUnavailable,
                0,
            ),
            BTreeMap::new(),
        );
    }
    let output = match run_allowlisted(&HostCommand::DockerList).await {
        Ok(output) => output,
        Err(error) => {
            return (
                Vec::new(),
                check(
                    CheckKind::Containers,
                    CheckStatus::Unavailable,
                    command_diagnostic(error),
                    0,
                ),
                BTreeMap::new(),
            );
        }
    };
    let mut containers = Vec::new();
    let mut deployments = BTreeMap::new();
    let mut partial = false;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if containers.len() >= 4096 {
            partial = true;
            break;
        }
        let row: Result<serde_json::Value, _> = serde_json::from_str(line);
        let Ok(row) = row else {
            partial = true;
            continue;
        };
        let id = row
            .get("ID")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let image = row
            .get("Image")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let name = row
            .get("Names")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim_start_matches('/');
        if !valid_container_id(id) || image.is_empty() || name.is_empty() {
            partial = true;
            continue;
        }
        match run_allowlisted(&HostCommand::DockerInspect {
            container_id: id.to_owned(),
        })
        .await
        {
            Ok(inspect) => match parse_docker_inspect(&inspect.stdout, id, name, image) {
                Some((container, deployment)) => {
                    if let Some(deployment) = deployment {
                        deployments.insert(container.id.clone(), deployment);
                    }
                    containers.push(container);
                }
                None => partial = true,
            },
            Err(_) => {
                partial = true;
                containers.push(ContainerRecord {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    image: image.to_owned(),
                    image_digest: None,
                    oci_revision: None,
                    oci_version: None,
                    oci_source: None,
                });
            }
        }
    }
    let status = if partial {
        CheckStatus::Partial
    } else {
        CheckStatus::Complete
    };
    let count = containers.len();
    (
        containers,
        check(
            CheckKind::Containers,
            status,
            DiagnosticCode::InvalidOutput,
            count,
        ),
        deployments,
    )
}

pub(crate) fn parse_docker_inspect(
    output: &[u8],
    fallback_id: &str,
    fallback_name: &str,
    fallback_image: &str,
) -> Option<(ContainerRecord, Option<DeploymentIdentity>)> {
    let line = std::str::from_utf8(output).ok()?.trim();
    let mut fields = line.split('\t');
    let id = fields.next()?.trim().trim_start_matches('/');
    let name = fields.next()?.trim().trim_start_matches('/');
    let image = fields.next()?.trim();
    let raw_image_digest = fields.next()?.trim();
    let revision = fields.next()?.trim();
    let version = fields.next()?.trim();
    let source = fields.next()?.trim();
    let id = if valid_container_id(id) {
        id
    } else {
        fallback_id
    };
    let name = if name.is_empty() { fallback_name } else { name };
    let image = if image.is_empty() {
        fallback_image
    } else {
        image
    };
    let image_digest = valid_sha256_digest(raw_image_digest);
    let oci_revision = if revision.is_empty() {
        None
    } else {
        normalize_commit(revision)
    };
    let oci_version = nonempty_bounded(version);
    let oci_source = validate_repository(source);
    let invalid_metadata = (!revision.is_empty() && oci_revision.is_none())
        || (!version.is_empty() && oci_version.is_none())
        || (!source.is_empty() && oci_source.is_none())
        || (!raw_image_digest.is_empty() && image_digest.is_none());
    let deploy = if invalid_metadata {
        Some(unknown_identity())
    } else if oci_revision.is_some()
        || oci_version.is_some()
        || oci_source.is_some()
        || image_digest.is_some()
    {
        Some(DeploymentIdentity {
            commit_sha: oci_revision.clone(),
            repository: oci_source.clone(),
            release_id: oci_version.clone(),
            image_digest: image_digest.clone(),
            built_at: None,
            source: DeploymentSource::OciLabel,
            integrity_verified: false,
        })
    } else {
        None
    };
    Some((
        ContainerRecord {
            id: id.to_owned(),
            name: name.to_owned(),
            image: image.to_owned(),
            image_digest,
            oci_revision,
            oci_version,
            oci_source,
        },
        deploy,
    ))
}
