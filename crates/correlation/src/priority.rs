use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use security_monitor_core::Environment;
use thiserror::Error;

const EPSS_MAX_AGE_DAYS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BusinessImpact {
    AuthenticationBoundary,
    CustomerData,
    SafetyCritical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsvcExploitation {
    Active,
    ProofOfConcept,
    None,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsvcAutomatability {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsvcImpact {
    Total,
    Partial,
    None,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsvcSignal {
    pub exploitation: SsvcExploitation,
    pub automatable: SsvcAutomatability,
    pub technical_impact: SsvcImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestCost {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PriorityContext {
    pub environment: Environment,
    pub internet_facing: Option<bool>,
    pub user_confirmed_reachable: bool,
    pub business_impacts: BTreeSet<BusinessImpact>,
    pub exploit_db_listed: bool,
    pub ssvc: Option<SsvcSignal>,
    pub fix_available: bool,
    pub test_cost: Option<TestCost>,
}

impl Default for PriorityContext {
    fn default() -> Self {
        Self {
            environment: Environment::Unknown,
            internet_facing: None,
            user_confirmed_reachable: false,
            business_impacts: BTreeSet::new(),
            exploit_db_listed: false,
            ssvc: None,
            fix_available: false,
            test_cost: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PriorityInput {
    pub cvss: Option<f64>,
    pub severity: Option<security_monitor_core::Severity>,
    pub kev_listed: bool,
    pub epss_score: Option<f64>,
    pub epss_date: Option<DateTime<Utc>>,
    pub context: PriorityContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityAssessment {
    pub score: u8,
    pub reasons: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PriorityError {
    #[error("CVSS score is outside the supported range")]
    InvalidCvss,
    #[error("EPSS score is outside the supported range")]
    InvalidEpss,
    #[error("EPSS timestamp is in the future")]
    FutureEpssTimestamp,
}

pub fn calculate_priority(
    input: &PriorityInput,
    evaluated_at: DateTime<Utc>,
) -> Result<PriorityAssessment, PriorityError> {
    validate_score(input.cvss, 10.0).map_err(|_| PriorityError::InvalidCvss)?;
    validate_score(input.epss_score, 1.0).map_err(|_| PriorityError::InvalidEpss)?;

    let mut score = 0_u16;
    let mut reasons = BTreeSet::new();
    match input.cvss {
        Some(cvss) => {
            score += (cvss * 5.0).round() as u16;
            reasons.insert("cvss_base".to_owned());
        }
        None => {
            let (base, reason) = severity_base(input.severity.as_ref());
            score += base;
            reasons.insert(reason.to_owned());
            reasons.insert("cvss_missing".to_owned());
        }
    }

    if input.kev_listed {
        score += 20;
        reasons.insert("kev_listed".to_owned());
    }

    match (input.epss_score, input.epss_date) {
        (Some(_), None) => {
            reasons.insert("epss_date_missing".to_owned());
        }
        (Some(_), Some(date)) if date > evaluated_at => {
            return Err(PriorityError::FutureEpssTimestamp);
        }
        (Some(_), Some(date)) if evaluated_at - date > Duration::days(EPSS_MAX_AGE_DAYS) => {
            reasons.insert("epss_stale".to_owned());
        }
        (Some(epss), Some(_)) if epss >= 0.5 => {
            score += 15;
            reasons.insert("epss_very_high".to_owned());
        }
        (Some(epss), Some(_)) if epss >= 0.1 => {
            score += 10;
            reasons.insert("epss_high".to_owned());
        }
        (Some(epss), Some(_)) if epss > 0.0 => {
            score += 5;
            reasons.insert("epss_elevated".to_owned());
        }
        (Some(_), Some(_)) => {
            reasons.insert("epss_low".to_owned());
        }
        (None, _) => {
            reasons.insert("epss_missing".to_owned());
        }
    }

    if input.context.exploit_db_listed {
        score += 10;
        reasons.insert("public_exploit".to_owned());
    }
    if let Some(ssvc) = input.context.ssvc {
        match ssvc.exploitation {
            SsvcExploitation::Active => {
                score += 15;
                reasons.insert("ssvc_exploitation_active".to_owned());
            }
            SsvcExploitation::ProofOfConcept => {
                score += 10;
                reasons.insert("ssvc_exploitation_poc".to_owned());
            }
            SsvcExploitation::None | SsvcExploitation::Unknown => {}
        }
        if ssvc.automatable == SsvcAutomatability::Yes {
            score += 10;
            reasons.insert("ssvc_automatable".to_owned());
        }
        match ssvc.technical_impact {
            SsvcImpact::Total => {
                score += 10;
                reasons.insert("ssvc_technical_impact_total".to_owned());
            }
            SsvcImpact::Partial => {
                score += 5;
                reasons.insert("ssvc_technical_impact_partial".to_owned());
            }
            SsvcImpact::None | SsvcImpact::Unknown => {}
        }
    }

    match input.context.environment {
        Environment::Production => {
            score += 5;
            reasons.insert("production".to_owned());
        }
        Environment::Unknown => {
            reasons.insert("environment_unknown".to_owned());
        }
        Environment::Staging | Environment::Development => {}
    }
    match input.context.internet_facing {
        Some(true) if input.context.environment == Environment::Production => {
            score += 10;
            reasons.insert("production_internet_facing".to_owned());
        }
        Some(true) => {
            score += 5;
            reasons.insert("internet_facing".to_owned());
        }
        None => {
            reasons.insert("internet_exposure_unknown".to_owned());
        }
        Some(false) => {}
    }
    if input.context.user_confirmed_reachable {
        score += 10;
        reasons.insert("user_confirmed_reachable".to_owned());
    }
    for impact in &input.context.business_impacts {
        let (points, reason) = match impact {
            BusinessImpact::AuthenticationBoundary => (5, "authentication_boundary"),
            BusinessImpact::CustomerData => (5, "customer_data_impact"),
            BusinessImpact::SafetyCritical => (10, "safety_critical_impact"),
        };
        score += points;
        reasons.insert(reason.to_owned());
    }
    if input.context.fix_available {
        score += 5;
        reasons.insert("fix_available".to_owned());
    }
    match input.context.test_cost {
        Some(TestCost::Medium) => {
            score += 1;
            reasons.insert("moderate_test_cost".to_owned());
        }
        Some(TestCost::High) => {
            score += 3;
            reasons.insert("high_test_cost".to_owned());
        }
        Some(TestCost::Low) | None => {}
    }

    let capped = score.min(100);
    if score > 100 {
        reasons.insert("score_capped_at_100".to_owned());
    }
    Ok(PriorityAssessment {
        score: capped as u8,
        reasons: reasons.into_iter().collect(),
    })
}

fn validate_score(score: Option<f64>, maximum: f64) -> Result<(), ()> {
    if score.is_some_and(|value| !value.is_finite() || !(0.0..=maximum).contains(&value)) {
        Err(())
    } else {
        Ok(())
    }
}

fn severity_base(severity: Option<&security_monitor_core::Severity>) -> (u16, &'static str) {
    match severity {
        Some(security_monitor_core::Severity::Critical) => (45, "severity_base_critical"),
        Some(security_monitor_core::Severity::High) => (38, "severity_base_high"),
        Some(security_monitor_core::Severity::Medium) => (28, "severity_base_medium"),
        Some(security_monitor_core::Severity::Low) => (18, "severity_base_low"),
        Some(security_monitor_core::Severity::Unknown) | None => (0, "severity_unknown"),
    }
}
