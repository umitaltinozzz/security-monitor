use security_monitor_core::AiTier;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::AiBudget;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AiTierAssignment {
    pub tier: AiTier,
    pub provider_id: Option<String>,
    pub fallback_provider_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct AiSettings {
    pub assignments: Vec<AiTierAssignment>,
    pub budget: AiBudget,
    pub triage_code_enabled: bool,
    pub enabled_tools: Vec<String>,
    #[serde(default)]
    pub mcp_source_access_projects: Vec<String>,
    #[serde(default = "default_memory_agent_writes_enabled")]
    pub memory_agent_writes_enabled: bool,
    #[serde(default = "default_memory_retention_days")]
    pub memory_retention_days: u32,
}

impl AiSettings {
    pub fn validate(&self) -> Result<(), AiSettingsError> {
        for limit in self
            .budget
            .daily_total_usd
            .into_iter()
            .chain(self.budget.monthly_total_usd)
        {
            if !limit.is_finite() || limit < 0.0 {
                return Err(AiSettingsError::InvalidBudget);
            }
        }
        if self
            .budget
            .daily_by_provider_usd
            .values()
            .chain(self.budget.monthly_by_provider_usd.values())
            .any(|limit| !limit.is_finite() || *limit < 0.0)
        {
            return Err(AiSettingsError::InvalidBudget);
        }
        let mut tiers = std::collections::BTreeSet::new();
        for assignment in &self.assignments {
            if !tiers.insert(format!("{:?}", assignment.tier)) {
                return Err(AiSettingsError::DuplicateTier);
            }
        }
        if self.enabled_tools.iter().any(|tool| !is_known_tool(tool)) {
            return Err(AiSettingsError::UnknownTool);
        }
        if self
            .enabled_tools
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != self.enabled_tools.len()
        {
            return Err(AiSettingsError::DuplicatePermission);
        }
        if self
            .mcp_source_access_projects
            .iter()
            .any(|project_id| project_id.is_empty() || project_id.len() > 128)
            || self
                .mcp_source_access_projects
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.mcp_source_access_projects.len()
        {
            return Err(AiSettingsError::DuplicatePermission);
        }
        if !(1..=3650).contains(&self.memory_retention_days) {
            return Err(AiSettingsError::InvalidMemoryRetention);
        }
        Ok(())
    }
}

impl Default for AiSettings {
    fn default() -> Self {
        load_default_settings()
    }
}

pub fn load_default_settings() -> AiSettings {
    serde_json::from_str(include_str!("../data/default-settings.json")).unwrap_or_else(|_| {
        AiSettings {
            assignments: vec![],
            budget: AiBudget::default(),
            triage_code_enabled: false,
            enabled_tools: vec![],
            mcp_source_access_projects: vec![],
            memory_agent_writes_enabled: default_memory_agent_writes_enabled(),
            memory_retention_days: default_memory_retention_days(),
        }
    })
}

fn is_known_tool(tool: &str) -> bool {
    matches!(
        tool,
        "list_projects"
            | "list_assets"
            | "list_findings"
            | "get_finding_evidence"
            | "compare_repo_deployment"
            | "read_project_file"
            | "search_project"
            | "analyze_impact"
            | "recall"
            | "remember"
            | "forget"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AiSettingsError {
    #[error("AI budget must be a finite non-negative amount")]
    InvalidBudget,
    #[error("AI tier may only be assigned once")]
    DuplicateTier,
    #[error("AI permissions contain a duplicate or invalid project")]
    DuplicatePermission,
    #[error("memory retention must be between 1 and 3650 days")]
    InvalidMemoryRetention,
    #[error("AI tool is not supported in this milestone")]
    UnknownTool,
}

fn default_memory_agent_writes_enabled() -> bool {
    true
}

fn default_memory_retention_days() -> u32 {
    180
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_data_driven_and_disable_paid_usage() {
        let settings = load_default_settings();
        assert_eq!(settings.budget.daily_total_usd, Some(0.0));
        assert_eq!(settings.budget.monthly_total_usd, Some(0.0));
        assert!(!settings.triage_code_enabled);
        assert!(settings.enabled_tools.is_empty());
        assert!(settings.mcp_source_access_projects.is_empty());
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn legacy_settings_keep_local_mcp_source_access_disabled() {
        let legacy = r#"{"assignments":[],"budget":{"daily_total_usd":0.0,"monthly_total_usd":0.0,"daily_by_provider_usd":{},"monthly_by_provider_usd":{}},"triage_code_enabled":false,"enabled_tools":["read_project_file"]}"#;
        let settings = serde_json::from_str::<AiSettings>(legacy).unwrap();
        assert!(settings.mcp_source_access_projects.is_empty());
        assert!(settings.memory_agent_writes_enabled);
        assert_eq!(settings.memory_retention_days, 180);
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn invalid_budget_and_unknown_tools_are_rejected() {
        let mut settings = AiSettings::default();
        settings.budget.daily_total_usd = Some(f64::NAN);
        assert_eq!(settings.validate(), Err(AiSettingsError::InvalidBudget));
        let mut settings = AiSettings::default();
        settings.enabled_tools.push("generic_exec".into());
        assert_eq!(settings.validate(), Err(AiSettingsError::UnknownTool));
        let settings = AiSettings {
            enabled_tools: vec!["list_projects".into(), "list_projects".into()],
            ..AiSettings::default()
        };
        assert_eq!(
            settings.validate(),
            Err(AiSettingsError::DuplicatePermission)
        );
        let settings = AiSettings {
            memory_retention_days: 0,
            ..AiSettings::default()
        };
        assert_eq!(
            settings.validate(),
            Err(AiSettingsError::InvalidMemoryRetention)
        );
        let settings = AiSettings {
            mcp_source_access_projects: vec!["project-1".into(), "project-1".into()],
            ..AiSettings::default()
        };
        assert_eq!(
            settings.validate(),
            Err(AiSettingsError::DuplicatePermission)
        );
    }
}
