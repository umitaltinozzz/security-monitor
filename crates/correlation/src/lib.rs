mod aliases;
mod correlate;
mod fingerprint;
mod matching;
mod priority;
mod state_machine;
mod version;

pub use aliases::AliasMerger;
pub use correlate::{
    CorrelatedFinding, CorrelationComponent, CorrelationError, InventoryFreshness,
    ScopeVerification, correlate, correlate_and_persist,
};
pub use fingerprint::{FindingFingerprintInput, FingerprintError, finding_fingerprint};
pub use matching::{AdvisoryFinding, FindingReason, evaluate_inventory};
pub use priority::{
    BusinessImpact, PriorityAssessment, PriorityContext, PriorityError, PriorityInput,
    SsvcAutomatability, SsvcExploitation, SsvcImpact, SsvcSignal, TestCost, calculate_priority,
};
pub use state_machine::{
    DispositionScope, StatusActor, StatusEvidence, StatusTransition, TransitionError,
    UserDisposition, apply_transition, validate_transition,
};
pub use version::{canonical_ecosystem, normalize_package_name};

#[cfg(test)]
mod tests;
