use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub finding_id: String,
    pub provider_id: String,
    pub requested_action: String,
    pub approval_state: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum McpRemediationAction {
    PreparePatch,
    RunSafeTests,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct McpRemediationRequest {
    pub id: String,
    pub action: McpRemediationAction,
    pub finding_id: String,
    pub provider_id: Option<String>,
    pub remediation_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

pub fn write_mcp_remediation_request(
    app_data_dir: &Path,
    request: &McpRemediationRequest,
) -> Result<(), RemediationError> {
    validate_mcp_request(request)?;
    let queue = canonical_mcp_queue_directory(app_data_dir)?;
    let path = queue.join(format!("{}.json", request.id));
    let bytes = serde_json::to_vec(request).map_err(|_| RemediationError::FilesystemFailed)?;
    if bytes.len() as u64 > MAX_MCP_REQUEST_BYTES {
        return Err(RemediationError::InvalidTestCommand);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| RemediationError::FilesystemFailed)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| RemediationError::FilesystemFailed)
}

pub fn list_mcp_remediation_requests(
    app_data_dir: &Path,
) -> Result<Vec<McpRemediationRequest>, RemediationError> {
    let queue = canonical_mcp_queue_directory(app_data_dir)?;
    let mut requests = Vec::new();
    for entry in fs::read_dir(&queue).map_err(|_| RemediationError::FilesystemFailed)? {
        let entry = entry.map_err(|_| RemediationError::FilesystemFailed)?;
        let file_type = entry
            .file_type()
            .map_err(|_| RemediationError::FilesystemFailed)?;
        if !file_type.is_file()
            || entry.path().extension().and_then(|ext| ext.to_str()) != Some("json")
        {
            continue;
        }
        let metadata = entry
            .metadata()
            .map_err(|_| RemediationError::FilesystemFailed)?;
        if metadata.len() > MAX_MCP_REQUEST_BYTES || requests.len() >= MAX_MCP_REQUESTS {
            return Err(RemediationError::InvalidTestCommand);
        }
        let bytes = fs::read(entry.path()).map_err(|_| RemediationError::FilesystemFailed)?;
        let request: McpRemediationRequest =
            serde_json::from_slice(&bytes).map_err(|_| RemediationError::InvalidTestCommand)?;
        validate_mcp_request(&request)?;
        if entry.file_name().to_string_lossy() != format!("{}.json", request.id) {
            return Err(RemediationError::InvalidTestCommand);
        }
        requests.push(request);
    }
    requests.sort_by_key(|request| request.created_at);
    Ok(requests)
}

pub fn remove_mcp_remediation_request(
    app_data_dir: &Path,
    request_id: &str,
) -> Result<(), RemediationError> {
    Uuid::parse_str(request_id).map_err(|_| RemediationError::InvalidTestCommand)?;
    let queue = canonical_mcp_queue_directory(app_data_dir)?;
    let path = queue.join(format!("{request_id}.json"));
    let metadata = fs::symlink_metadata(&path).map_err(|_| RemediationError::FilesystemFailed)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(RemediationError::InvalidTestCommand);
    }
    fs::remove_file(path).map_err(|_| RemediationError::FilesystemFailed)
}

fn validate_mcp_request(request: &McpRemediationRequest) -> Result<(), RemediationError> {
    Uuid::parse_str(&request.id).map_err(|_| RemediationError::InvalidTestCommand)?;
    for value in [
        &request.finding_id,
        request.provider_id.as_deref().unwrap_or(""),
        request.remediation_id.as_deref().unwrap_or(""),
    ] {
        if value.len() > 128 || value.chars().any(char::is_control) {
            return Err(RemediationError::InvalidTestCommand);
        }
    }
    match request.action {
        McpRemediationAction::PreparePatch
            if request.finding_id.is_empty()
                || request.provider_id.as_deref().is_none_or(str::is_empty)
                || request.remediation_id.is_some() =>
        {
            Err(RemediationError::InvalidTestCommand)
        }
        McpRemediationAction::RunSafeTests
            if request.finding_id.is_empty()
                || request.remediation_id.as_deref().is_none_or(str::is_empty)
                || request.provider_id.is_some() =>
        {
            Err(RemediationError::InvalidTestCommand)
        }
        _ => Ok(()),
    }
}

fn canonical_mcp_queue_directory(app_data_dir: &Path) -> Result<PathBuf, RemediationError> {
    fs::create_dir_all(app_data_dir).map_err(|_| RemediationError::FilesystemFailed)?;
    let canonical_data =
        fs::canonicalize(app_data_dir).map_err(|_| RemediationError::FilesystemFailed)?;
    let directory = canonical_data.join("mcp-remediation-queue");
    fs::create_dir_all(&directory).map_err(|_| RemediationError::FilesystemFailed)?;
    let canonical_directory =
        fs::canonicalize(directory).map_err(|_| RemediationError::FilesystemFailed)?;
    if !canonical_directory.starts_with(&canonical_data) {
        return Err(RemediationError::WorktreePathInvalid);
    }
    Ok(canonical_directory)
}
