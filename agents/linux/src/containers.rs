use super::*;
use crate::deploy::unknown_identity;

const MAX_CONTAINERS: usize = 4096;
const DOCKER_INSPECT_BATCH_SIZE: usize = 128;

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
    let mut candidates = Vec::new();
    let mut partial = false;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if candidates.len() >= MAX_CONTAINERS {
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
        candidates.push((id.to_owned(), name.to_owned(), image.to_owned()));
    }
    let mut deployments = BTreeMap::new();
    let mut containers = Vec::with_capacity(candidates.len());
    for batch in candidates.chunks(DOCKER_INSPECT_BATCH_SIZE) {
        let ids = batch
            .iter()
            .map(|(id, _, _)| id.clone())
            .collect::<Vec<_>>();
        match run_allowlisted(&HostCommand::DockerInspect { container_ids: ids }).await {
            Ok(inspect) => {
                let mut inspected = BTreeSet::new();
                for line in String::from_utf8_lossy(&inspect.stdout).lines() {
                    let returned_id = line.split('\t').next().unwrap_or_default().trim();
                    let Some((id, name, image)) = batch
                        .iter()
                        .find(|(id, _, _)| id.eq_ignore_ascii_case(returned_id))
                    else {
                        partial = true;
                        continue;
                    };
                    if !inspected.insert(id.to_ascii_lowercase()) {
                        partial = true;
                        continue;
                    }
                    match parse_docker_inspect(line.as_bytes(), id, name, image) {
                        Some((container, deployment)) => {
                            if let Some(deployment) = deployment {
                                deployments.insert(container.id.clone(), deployment);
                            }
                            containers.push(container);
                        }
                        None => {
                            partial = true;
                            containers.push(fallback_container(id, name, image));
                        }
                    }
                }
                for (id, name, image) in batch {
                    if !inspected.contains(&id.to_ascii_lowercase()) {
                        partial = true;
                        containers.push(fallback_container(id, name, image));
                    }
                }
            }
            Err(_) => {
                partial = true;
                containers.extend(
                    batch
                        .iter()
                        .map(|(id, name, image)| fallback_container(id, name, image)),
                );
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

fn fallback_container(id: &str, name: &str, image: &str) -> ContainerRecord {
    ContainerRecord {
        id: id.to_owned(),
        name: name.to_owned(),
        image: image.to_owned(),
        image_digest: None,
        oci_revision: None,
        oci_version: None,
        oci_source: None,
    }
}

pub(crate) fn parse_docker_inspect(
    output: &[u8],
    fallback_id: &str,
    fallback_name: &str,
    fallback_image: &str,
) -> Option<(ContainerRecord, Option<DeploymentIdentity>)> {
    let line = std::str::from_utf8(output)
        .ok()?
        .trim_end_matches(['\r', '\n']);
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
