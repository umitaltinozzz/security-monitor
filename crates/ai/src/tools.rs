use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPermission {
    Read,
    Scan,
    AiApproval,
    Write,
    Execute,
    Export,
    MemoryWrite,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub permission: ToolPermission,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Error, PartialEq)]
pub enum ToolError {
    #[error("the requested tool is not enabled")]
    NotEnabled,
    #[error("the tool permission has not been approved")]
    ApprovalRequired,
    #[error("tool arguments are invalid")]
    InvalidArguments,
}

#[async_trait::async_trait]
pub trait ToolExecutor: Send + Sync {
    async fn execute(&self, call: &ToolCall) -> Result<Value, ToolError>;
}

pub fn authorize_tool(
    tool: &AiTool,
    permitted_tool_names: &[String],
    approved_permissions: &[ToolPermission],
) -> Result<(), ToolError> {
    if !permitted_tool_names.iter().any(|name| name == &tool.name) {
        return Err(ToolError::NotEnabled);
    }
    if matches!(tool.permission, ToolPermission::Read)
        || approved_permissions.contains(&tool.permission)
    {
        Ok(())
    } else {
        Err(ToolError::ApprovalRequired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(permission: ToolPermission) -> AiTool {
        AiTool {
            name: "read_project_file".into(),
            description: "Read one permitted file".into(),
            input_schema: serde_json::json!({"type":"object"}),
            permission,
        }
    }

    #[test]
    fn tools_require_both_allowlisting_and_non_read_permission_approval() {
        let allowed = vec!["read_project_file".to_owned()];
        assert_eq!(
            authorize_tool(&tool(ToolPermission::Read), &allowed, &[]),
            Ok(())
        );
        assert_eq!(
            authorize_tool(&tool(ToolPermission::Scan), &allowed, &[]),
            Err(ToolError::ApprovalRequired)
        );
        assert_eq!(
            authorize_tool(&tool(ToolPermission::Read), &[], &[]),
            Err(ToolError::NotEnabled)
        );
    }
}
