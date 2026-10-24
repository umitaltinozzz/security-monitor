mod budget;
mod config;
mod provider;
mod redaction;
mod tools;

pub use budget::{AiBudget, BudgetDecision, BudgetError, enforce_budget, estimate_cost};
pub use config::{AiSettings, AiTierAssignment, load_default_settings};
pub use provider::{
    AiError, AiRequest, AiResponse, AiTransport, DataCategory, HttpAiTransport,
    MAX_OUTPUT_TOKENS_PER_CALL, MAX_TOOL_CONTEXT_BYTES, TransferApproval, TransferApprovalInput,
    create_transfer_approval, maximum_run_token_bounds, run_tool_loop, validate_provider_config,
};
pub use redaction::{
    RedactionResult, is_sensitive_path, redact_relative_path, redact_text,
    redact_text_with_host_aliases,
};
pub use tools::{AiTool, ToolCall, ToolError, ToolExecutor, ToolPermission, authorize_tool};
