use chrono::{DateTime, Utc};
use security_monitor_core::{Finding, FindingDisposition, FindingDispositionReason, FindingStatus};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusActor {
    System,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispositionScope {
    Finding,
    Project,
    Asset,
    Deployment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDisposition {
    pub reason: FindingDispositionReason,
    pub scope: DispositionScope,
    pub scope_id: String,
    pub expires_at: Option<DateTime<Utc>>,
}

impl DispositionScope {
    fn label(self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Project => "project",
            Self::Asset => "asset",
            Self::Deployment => "deployment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusEvidence {
    UserAction,
    CurrentDataIncomplete,
    AffectedVersionVerified,
    MitigationVerified,
    FixProposed,
    ReferenceBranchFixVerified,
    ProductionFixVerified,
    DispositionExpired,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatusTransition {
    pub from: FindingStatus,
    pub to: FindingStatus,
    pub actor: StatusActor,
    pub evidence: StatusEvidence,
    pub disposition: Option<UserDisposition>,
    pub current_risk_expires_at: Option<DateTime<Utc>>,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransitionError {
    #[error("finding status is unchanged")]
    Noop,
    #[error("finding status changed before this transition was applied")]
    SourceStatusChanged,
    #[error("finding-scoped disposition refers to a different finding")]
    FindingScopeMismatch,
    #[error("risk expiry changed before this transition was applied")]
    RiskExpiryChanged,
    #[error("system transition is not authorized by its evidence")]
    SystemEvidenceRequired,
    #[error("this status requires verified system evidence")]
    UserCannotAssignVerifiedStatus,
    #[error("only the user may assign this finding status")]
    UserActionRequired,
    #[error("user status changes require a scoped reason")]
    DispositionRequired,
    #[error("disposition reason does not apply to the selected status")]
    InvalidDispositionReason,
    #[error("accepted risk and false positive require a future expiry")]
    ExpiryRequired,
    #[error("disposition expiry must be in the future")]
    InvalidExpiry,
    #[error("finding disposition has not expired")]
    DispositionNotExpired,
}

pub fn validate_transition(
    transition: &StatusTransition,
) -> Result<Option<FindingDisposition>, TransitionError> {
    if transition.from == transition.to {
        return Err(TransitionError::Noop);
    }
    match transition.actor {
        StatusActor::User => validate_user_transition(transition),
        StatusActor::System => validate_system_transition(transition),
    }
}

pub fn apply_transition(
    finding: &mut Finding,
    transition: &StatusTransition,
) -> Result<(), TransitionError> {
    if finding.status != transition.from {
        return Err(TransitionError::SourceStatusChanged);
    }
    if transition.disposition.as_ref().is_some_and(|value| {
        value.scope == DispositionScope::Finding && value.scope_id != finding.id
    }) {
        return Err(TransitionError::FindingScopeMismatch);
    }
    if transition.evidence == StatusEvidence::DispositionExpired
        && transition.current_risk_expires_at != finding.risk_expires_at
    {
        return Err(TransitionError::RiskExpiryChanged);
    }
    let disposition = validate_transition(transition)?;
    finding.status = transition.to.clone();
    finding.risk_expires_at = disposition.as_ref().and_then(|value| value.expires_at);
    finding.disposition = disposition;
    finding.updated_at = transition.at;
    Ok(())
}

fn validate_user_transition(
    transition: &StatusTransition,
) -> Result<Option<FindingDisposition>, TransitionError> {
    if transition.evidence != StatusEvidence::UserAction {
        return Err(TransitionError::SystemEvidenceRequired);
    }
    if !matches!(
        transition.to,
        FindingStatus::NotReachable | FindingStatus::AcceptedRisk | FindingStatus::FalsePositive
    ) {
        return Err(TransitionError::UserCannotAssignVerifiedStatus);
    }
    let disposition = transition
        .disposition
        .as_ref()
        .filter(|value| !value.scope_id.trim().is_empty())
        .ok_or(TransitionError::DispositionRequired)?;
    if !reason_matches_status(disposition.reason, &transition.to) {
        return Err(TransitionError::InvalidDispositionReason);
    }
    let requires_expiry = matches!(
        transition.to,
        FindingStatus::AcceptedRisk | FindingStatus::FalsePositive
    );
    if requires_expiry {
        let expiry = disposition
            .expires_at
            .ok_or(TransitionError::ExpiryRequired)?;
        if expiry <= transition.at {
            return Err(TransitionError::InvalidExpiry);
        }
    } else if disposition
        .expires_at
        .is_some_and(|expiry| expiry <= transition.at)
    {
        return Err(TransitionError::InvalidExpiry);
    }
    if matches!(
        transition.to,
        FindingStatus::NotReachable | FindingStatus::AcceptedRisk | FindingStatus::FalsePositive
    ) {
        Ok(Some(FindingDisposition {
            reason: disposition.reason,
            scope: disposition.scope.label().to_owned(),
            scope_id: disposition.scope_id.trim().to_owned(),
            set_at: transition.at,
            expires_at: disposition.expires_at,
        }))
    } else {
        Ok(None)
    }
}

fn reason_matches_status(reason: FindingDispositionReason, status: &FindingStatus) -> bool {
    match status {
        FindingStatus::AcceptedRisk => matches!(
            reason,
            FindingDispositionReason::BusinessAccepted
                | FindingDispositionReason::CompensatingControl
                | FindingDispositionReason::TemporaryException
                | FindingDispositionReason::FixPlanned
        ),
        FindingStatus::FalsePositive => matches!(
            reason,
            FindingDispositionReason::DuplicateFinding
                | FindingDispositionReason::IncorrectPackage
                | FindingDispositionReason::UnaffectedVersion
                | FindingDispositionReason::NoAffectedCodePath
                | FindingDispositionReason::OtherReviewed
        ),
        FindingStatus::NotReachable => matches!(
            reason,
            FindingDispositionReason::NoAffectedCodePath
                | FindingDispositionReason::ConfigurationPreventsReachability
                | FindingDispositionReason::OtherReviewed
        ),
        _ => true,
    }
}

fn validate_system_transition(
    transition: &StatusTransition,
) -> Result<Option<FindingDisposition>, TransitionError> {
    let valid = match (transition.evidence, &transition.from, &transition.to) {
        (
            StatusEvidence::CurrentDataIncomplete,
            FindingStatus::New
            | FindingStatus::ConfirmedAffected
            | FindingStatus::Mitigated
            | FindingStatus::FixProposed
            | FindingStatus::FixedInRepo
            | FindingStatus::FixedInProduction,
            FindingStatus::NeedsReview,
        ) => true,
        (
            StatusEvidence::AffectedVersionVerified,
            FindingStatus::New
            | FindingStatus::NeedsReview
            | FindingStatus::Mitigated
            | FindingStatus::FixProposed
            | FindingStatus::FixedInRepo
            | FindingStatus::FixedInProduction
            | FindingStatus::NotReachable,
            FindingStatus::ConfirmedAffected,
        ) => true,
        (
            StatusEvidence::MitigationVerified,
            FindingStatus::ConfirmedAffected,
            FindingStatus::Mitigated,
        ) => true,
        (
            StatusEvidence::FixProposed,
            FindingStatus::ConfirmedAffected | FindingStatus::Mitigated,
            FindingStatus::FixProposed,
        ) => true,
        (
            StatusEvidence::ReferenceBranchFixVerified,
            FindingStatus::ConfirmedAffected
            | FindingStatus::Mitigated
            | FindingStatus::FixProposed,
            FindingStatus::FixedInRepo,
        ) => true,
        (
            StatusEvidence::ProductionFixVerified,
            FindingStatus::ConfirmedAffected
            | FindingStatus::Mitigated
            | FindingStatus::FixProposed
            | FindingStatus::FixedInRepo,
            FindingStatus::FixedInProduction,
        ) => true,
        (
            StatusEvidence::DispositionExpired,
            FindingStatus::AcceptedRisk | FindingStatus::FalsePositive,
            FindingStatus::New,
        ) => transition
            .current_risk_expires_at
            .is_some_and(|expiry| expiry <= transition.at),
        _ => false,
    };
    if !valid {
        if matches!(
            transition.to,
            FindingStatus::NotReachable
                | FindingStatus::AcceptedRisk
                | FindingStatus::FalsePositive
        ) {
            return Err(TransitionError::UserActionRequired);
        }
        if transition.evidence == StatusEvidence::DispositionExpired
            && transition.current_risk_expires_at.is_some()
        {
            return Err(TransitionError::DispositionNotExpired);
        }
        return Err(TransitionError::SystemEvidenceRequired);
    }
    Ok(None)
}
