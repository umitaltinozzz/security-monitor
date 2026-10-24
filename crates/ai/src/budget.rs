use chrono::{DateTime, Datelike, NaiveTime, Utc};
use security_monitor_core::{AiProvider, AiRun};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ts_rs::TS;

/// Limits are expressed in USD and are configured by the user. `Some(0.0)` disables paid usage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
pub struct AiBudget {
    pub daily_total_usd: Option<f64>,
    pub monthly_total_usd: Option<f64>,
    pub daily_by_provider_usd: std::collections::BTreeMap<String, f64>,
    pub monthly_by_provider_usd: std::collections::BTreeMap<String, f64>,
}

impl Default for AiBudget {
    fn default() -> Self {
        Self {
            daily_total_usd: Some(0.0),
            monthly_total_usd: Some(0.0),
            daily_by_provider_usd: Default::default(),
            monthly_by_provider_usd: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct BudgetDecision {
    pub estimated_cost_usd: f64,
    pub daily_total_after_usd: f64,
    pub monthly_total_after_usd: f64,
    pub daily_provider_after_usd: f64,
    pub monthly_provider_after_usd: f64,
}

#[derive(Debug, Error, PartialEq)]
pub enum BudgetError {
    #[error("provider pricing is incomplete")]
    UnknownPrice,
    #[error("estimated request cost is invalid")]
    InvalidEstimate,
    #[error("AI daily or monthly budget would be exceeded")]
    LimitExceeded,
    #[error("usage history contains an unknown cost; budget cannot be verified")]
    UnknownHistoricalCost,
}

pub fn estimate_cost(
    provider: &AiProvider,
    input_tokens: u64,
    output_tokens: u64,
) -> Result<f64, BudgetError> {
    let input_rate = provider.price_in.ok_or(BudgetError::UnknownPrice)?;
    let output_rate = provider.price_out.ok_or(BudgetError::UnknownPrice)?;
    if !input_rate.is_finite() || !output_rate.is_finite() || input_rate < 0.0 || output_rate < 0.0
    {
        return Err(BudgetError::InvalidEstimate);
    }
    let cost =
        (input_tokens as f64 * input_rate + output_tokens as f64 * output_rate) / 1_000_000.0;
    if cost.is_finite() {
        Ok(cost)
    } else {
        Err(BudgetError::InvalidEstimate)
    }
}

pub fn enforce_budget(
    budget: &AiBudget,
    provider: &AiProvider,
    runs: &[AiRun],
    estimate: f64,
    now: DateTime<Utc>,
) -> Result<BudgetDecision, BudgetError> {
    if !estimate.is_finite() || estimate < 0.0 {
        return Err(BudgetError::InvalidEstimate);
    }
    let day_start = now.date_naive().and_time(NaiveTime::MIN).and_utc();
    let month_start = now
        .date_naive()
        .with_day(1)
        .unwrap_or(now.date_naive())
        .and_time(NaiveTime::MIN)
        .and_utc();
    let (daily_total, monthly_total, daily_provider, monthly_provider) =
        usage_since(runs, &provider.id, day_start, month_start)?;
    let result = BudgetDecision {
        estimated_cost_usd: estimate,
        daily_total_after_usd: daily_total + estimate,
        monthly_total_after_usd: monthly_total + estimate,
        daily_provider_after_usd: daily_provider + estimate,
        monthly_provider_after_usd: monthly_provider + estimate,
    };
    check_limit(budget.daily_total_usd, result.daily_total_after_usd)?;
    check_limit(budget.monthly_total_usd, result.monthly_total_after_usd)?;
    check_limit(
        budget.daily_by_provider_usd.get(&provider.id).copied(),
        result.daily_provider_after_usd,
    )?;
    check_limit(
        budget.monthly_by_provider_usd.get(&provider.id).copied(),
        result.monthly_provider_after_usd,
    )?;
    Ok(result)
}

fn usage_since(
    runs: &[AiRun],
    provider_id: &str,
    day_start: DateTime<Utc>,
    month_start: DateTime<Utc>,
) -> Result<(f64, f64, f64, f64), BudgetError> {
    let mut daily_total = 0.0;
    let mut monthly_total = 0.0;
    let mut daily_provider = 0.0;
    let mut monthly_provider = 0.0;
    for run in runs.iter().filter(|run| run.started_at >= month_start) {
        let cost = run.cost.ok_or(BudgetError::UnknownHistoricalCost)?;
        if !cost.is_finite() || cost < 0.0 {
            return Err(BudgetError::UnknownHistoricalCost);
        }
        monthly_total += cost;
        if run.provider_id == provider_id {
            monthly_provider += cost;
        }
        if run.started_at >= day_start {
            daily_total += cost;
            if run.provider_id == provider_id {
                daily_provider += cost;
            }
        }
    }
    Ok((daily_total, monthly_total, daily_provider, monthly_provider))
}

fn check_limit(limit: Option<f64>, amount: f64) -> Result<(), BudgetError> {
    if limit.is_some_and(|limit| !limit.is_finite() || limit < 0.0 || amount > limit) {
        Err(BudgetError::LimitExceeded)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};
    use security_monitor_core::{AiProviderKind, AiTier, ProviderCapabilities};

    fn provider() -> AiProvider {
        AiProvider {
            id: "provider-a".into(),
            kind: AiProviderKind::OpenAiCompatible,
            display_name: "Test provider".into(),
            base_url: Some("https://api.example.test/v1".into()),
            model: Some("user-entered-model".into()),
            capabilities: ProviderCapabilities {
                tool_calling: true,
                context_window: None,
                json_mode: false,
            },
            price_in: Some(1.0),
            price_out: Some(2.0),
            data_region: Some("user selected".into()),
            keychain_ref: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn estimates_cost_and_rejects_over_budget_before_a_request() {
        let provider = provider();
        let cost = estimate_cost(&provider, 100_000, 100_000).unwrap();
        assert_eq!(cost, 0.3);
        let budget = AiBudget {
            daily_total_usd: Some(0.25),
            ..AiBudget::default()
        };
        let when = Utc.with_ymd_and_hms(2026, 1, 2, 12, 0, 0).unwrap();
        assert_eq!(
            enforce_budget(&budget, &provider, &[], cost, when),
            Err(BudgetError::LimitExceeded)
        );
    }

    #[test]
    fn missing_price_or_historical_usage_never_bypasses_limits() {
        let mut provider = provider();
        provider.price_in = None;
        assert_eq!(
            estimate_cost(&provider, 1, 1),
            Err(BudgetError::UnknownPrice)
        );
        provider.price_in = Some(1.0);
        let now = Utc.with_ymd_and_hms(2026, 1, 2, 12, 0, 0).unwrap();
        let run = AiRun {
            id: "run".into(),
            provider_id: provider.id.clone(),
            model: "model".into(),
            tier: AiTier::Analysis,
            finding_id: None,
            tokens_in: 1,
            tokens_out: 1,
            cost: None,
            files_sent: vec![],
            started_at: now - Duration::minutes(1),
            outcome: "failed".into(),
        };
        assert_eq!(
            enforce_budget(&AiBudget::default(), &provider, &[run], 0.0, now),
            Err(BudgetError::UnknownHistoricalCost)
        );
    }
}
