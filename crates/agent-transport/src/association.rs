use security_monitor_agent_protocol::{DeploymentIdentity, normalize_commit};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProjectIdentity {
    pub id: String,
    pub name: String,
    pub git_remote: Option<String>,
    pub reference_commit: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationMatch {
    RepositoryAndCommit,
    Repository,
    Commit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectAssociationSuggestion {
    pub project_id: String,
    pub project_name: String,
    pub matched_by: AssociationMatch,
}

/// Returns local-only project suggestions; it never writes or uploads a project association.
pub fn suggest_project_associations(
    deployment: &DeploymentIdentity,
    projects: &[LocalProjectIdentity],
) -> Vec<ProjectAssociationSuggestion> {
    let deployment_repository = deployment
        .repository
        .as_deref()
        .and_then(normalize_repository);
    let deployment_commit = deployment.commit_sha.as_deref().and_then(normalize_commit);
    let mut suggestions = projects
        .iter()
        .filter_map(|project| {
            let repository_matches = deployment_repository.is_some()
                && project.git_remote.as_deref().and_then(normalize_repository)
                    == deployment_repository;
            let commit_matches = deployment_commit.is_some()
                && project
                    .reference_commit
                    .as_deref()
                    .and_then(normalize_commit)
                    == deployment_commit;
            let matched_by = match (repository_matches, commit_matches) {
                (true, true) => AssociationMatch::RepositoryAndCommit,
                (true, false) => AssociationMatch::Repository,
                (false, true) => AssociationMatch::Commit,
                (false, false) => return None,
            };
            Some(ProjectAssociationSuggestion {
                project_id: project.id.clone(),
                project_name: project.name.clone(),
                matched_by,
            })
        })
        .collect::<Vec<_>>();
    suggestions.sort_by(|left, right| {
        association_rank(left.matched_by)
            .cmp(&association_rank(right.matched_by))
            .then_with(|| left.project_id.cmp(&right.project_id))
    });
    suggestions
}

fn association_rank(matched_by: AssociationMatch) -> u8 {
    match matched_by {
        AssociationMatch::RepositoryAndCommit => 0,
        AssociationMatch::Repository => 1,
        AssociationMatch::Commit => 2,
    }
}

fn normalize_repository(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 2048
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return None;
    }
    let normalized = if value.contains("://") {
        let url = url::Url::parse(value).ok()?;
        if !matches!(url.scheme(), "https" | "http")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        format!(
            "{}://{}{}",
            url.scheme().to_ascii_lowercase(),
            url.host_str()?.to_ascii_lowercase(),
            url.path()
        )
    } else {
        let remote = value.strip_prefix("git@")?;
        let (host, path) = remote.split_once(':')?;
        if host.is_empty()
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
            || path.is_empty()
            || path.starts_with('/')
        {
            return None;
        }
        format!("https://{host}/{path}")
    };
    let normalized = normalized.trim_end_matches('/').trim_end_matches(".git");
    Some(normalized.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use security_monitor_agent_protocol::DeploymentSource;

    use super::{AssociationMatch, LocalProjectIdentity, suggest_project_associations};

    #[test]
    fn deployment_repository_and_commit_produce_local_suggestions_without_auto_assignment() {
        let deployment = security_monitor_agent_protocol::DeploymentIdentity {
            commit_sha: Some("ABCDEF0123456789".to_owned()),
            repository: Some("https://github.com/acme/web".to_owned()),
            release_id: None,
            image_digest: None,
            built_at: None,
            source: DeploymentSource::ApplicationFile,
            integrity_verified: false,
        };
        let projects = vec![
            LocalProjectIdentity {
                id: "project-b".to_owned(),
                name: "Web service".to_owned(),
                git_remote: Some("git@github.com:acme/web.git".to_owned()),
                reference_commit: Some("abcdef0123456789".to_owned()),
            },
            LocalProjectIdentity {
                id: "project-a".to_owned(),
                name: "Web mirror".to_owned(),
                git_remote: Some("https://github.com/acme/web.git".to_owned()),
                reference_commit: None,
            },
        ];
        let suggestions = suggest_project_associations(&deployment, &projects);
        assert_eq!(suggestions.len(), 2);
        assert_eq!(suggestions[0].project_id, "project-b");
        assert_eq!(
            suggestions[0].matched_by,
            AssociationMatch::RepositoryAndCommit
        );
        assert_eq!(suggestions[1].matched_by, AssociationMatch::Repository);
        assert_eq!(projects.len(), 2);
    }
}
