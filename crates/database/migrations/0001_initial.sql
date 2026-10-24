PRAGMA foreign_keys = ON;

CREATE TABLE app_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0)
);
INSERT INTO app_metadata (singleton, schema_version) VALUES (1, 1);

CREATE TABLE projects (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    name TEXT NOT NULL CHECK (length(name) > 0),
    root_path TEXT NOT NULL CHECK (length(root_path) > 0),
    git_remote TEXT,
    reference_branch TEXT,
    allowed_ai_providers TEXT NOT NULL CHECK (json_valid(allowed_ai_providers) AND json_type(allowed_ai_providers) = 'array'),
    last_scan_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE assets (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    type TEXT NOT NULL CHECK (type IN ('server', 'container', 'runtime')),
    hostname_alias TEXT NOT NULL CHECK (length(hostname_alias) > 0),
    environment TEXT NOT NULL CHECK (environment IN ('production', 'staging', 'development', 'unknown')),
    ssh_target_ref TEXT,
    host_key_fingerprint TEXT,
    last_seen_at TEXT,
    last_success_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE services (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    service_name TEXT NOT NULL CHECK (length(service_name) > 0),
    runtime_binary TEXT,
    runtime_version TEXT,
    internet_facing INTEGER NOT NULL CHECK (internet_facing IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE deployments (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    commit_sha TEXT,
    image_digest TEXT,
    release_id TEXT,
    id_source TEXT NOT NULL CHECK (length(id_source) > 0),
    observed_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE components (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    purl TEXT NOT NULL UNIQUE CHECK (length(purl) > 0),
    ecosystem TEXT NOT NULL CHECK (length(ecosystem) > 0),
    name TEXT NOT NULL CHECK (length(name) > 0),
    version TEXT NOT NULL CHECK (length(version) > 0),
    source_type TEXT NOT NULL CHECK (length(source_type) > 0),
    created_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE component_instances (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    component_id TEXT NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    asset_id TEXT REFERENCES assets(id) ON DELETE CASCADE,
    service_id TEXT REFERENCES services(id) ON DELETE CASCADE,
    deployment_id TEXT REFERENCES deployments(id) ON DELETE CASCADE,
    evidence TEXT NOT NULL CHECK (json_valid(evidence) AND json_type(evidence) = 'array'),
    created_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    CHECK (project_id IS NOT NULL OR asset_id IS NOT NULL OR service_id IS NOT NULL OR deployment_id IS NOT NULL)
);

CREATE TABLE advisories (
    canonical_id TEXT PRIMARY KEY NOT NULL CHECK (length(canonical_id) > 0),
    aliases TEXT NOT NULL CHECK (json_valid(aliases) AND json_type(aliases) = 'array'),
    affected_ranges TEXT NOT NULL CHECK (json_valid(affected_ranges) AND json_type(affected_ranges) = 'array'),
    fixed_versions TEXT NOT NULL CHECK (json_valid(fixed_versions) AND json_type(fixed_versions) = 'array'),
    cvss REAL CHECK (cvss IS NULL OR (cvss >= 0 AND cvss <= 10)),
    severity TEXT CHECK (severity IS NULL OR severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    kev INTEGER NOT NULL CHECK (kev IN (0, 1)),
    epss REAL CHECK (epss IS NULL OR (epss >= 0 AND epss <= 1)),
    epss_date TEXT,
    source_urls TEXT NOT NULL CHECK (json_valid(source_urls) AND json_type(source_urls) = 'array'),
    source_updated_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    advisory_id TEXT NOT NULL REFERENCES advisories(canonical_id) ON DELETE RESTRICT,
    component_instance_id TEXT NOT NULL REFERENCES component_instances(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('new', 'needs_review', 'confirmed_affected', 'not_reachable', 'mitigated', 'fix_proposed', 'fixed_in_repo', 'fixed_in_production', 'accepted_risk', 'false_positive')),
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    priority_score INTEGER NOT NULL CHECK (priority_score BETWEEN 0 AND 100),
    priority_reasons TEXT NOT NULL CHECK (json_valid(priority_reasons) AND json_type(priority_reasons) = 'array'),
    fingerprint TEXT NOT NULL UNIQUE CHECK (length(fingerprint) > 0),
    repo_status TEXT NOT NULL CHECK (repo_status IN ('unknown', 'still_affected', 'fixed_in_repo')),
    production_status TEXT NOT NULL CHECK (production_status IN ('unknown', 'still_affected', 'fixed_in_production')),
    risk_expires_at TEXT,
    fix_version TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE finding_evidence (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL CHECK (length(evidence_type) > 0),
    file_path_redacted TEXT,
    reference TEXT,
    confidence REAL CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    created_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE scan_runs (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    scope TEXT NOT NULL CHECK (json_valid(scope) AND json_type(scope) = 'object'),
    scanner TEXT NOT NULL CHECK (length(scanner) > 0),
    scanner_version TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled')),
    error TEXT,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE remediations (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    worktree_path TEXT NOT NULL CHECK (length(worktree_path) > 0),
    branch TEXT NOT NULL CHECK (length(branch) > 0),
    diff_hash TEXT,
    tests TEXT NOT NULL CHECK (json_valid(tests) AND json_type(tests) = 'array'),
    approval_state TEXT NOT NULL CHECK (approval_state IN ('pending', 'approved', 'rejected', 'cancelled')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE ai_providers (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    kind TEXT NOT NULL CHECK (kind IN ('agent_cli', 'open_ai_compatible', 'anthropic', 'local')),
    display_name TEXT NOT NULL CHECK (length(display_name) > 0),
    base_url TEXT,
    model TEXT,
    capabilities TEXT NOT NULL CHECK (json_valid(capabilities) AND json_type(capabilities) = 'object'),
    price_in REAL CHECK (price_in IS NULL OR price_in >= 0),
    price_out REAL CHECK (price_out IS NULL OR price_out >= 0),
    data_region TEXT,
    keychain_ref TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE ai_runs (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    provider_id TEXT NOT NULL REFERENCES ai_providers(id) ON DELETE RESTRICT,
    tier TEXT NOT NULL CHECK (tier IN ('triage', 'analysis', 'patch')),
    finding_id TEXT REFERENCES findings(id) ON DELETE SET NULL,
    tokens_in INTEGER NOT NULL CHECK (tokens_in >= 0),
    tokens_out INTEGER NOT NULL CHECK (tokens_out >= 0),
    cost REAL CHECK (cost IS NULL OR cost >= 0),
    files_sent TEXT NOT NULL CHECK (json_valid(files_sent) AND json_type(files_sent) = 'array'),
    started_at TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (length(outcome) > 0),
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE notification_channels (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    kind TEXT NOT NULL CHECK (kind IN ('desktop', 'webhook', 'slack', 'discord', 'smtp')),
    config_ref TEXT,
    min_priority INTEGER NOT NULL CHECK (min_priority BETWEEN 0 AND 100),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL CHECK (length(actor) > 0),
    action TEXT NOT NULL CHECK (length(action) > 0),
    scope_json TEXT NOT NULL CHECK (json_valid(scope_json) AND json_type(scope_json) = 'object'),
    result TEXT NOT NULL CHECK (result IN ('succeeded', 'denied', 'failed')),
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE INDEX idx_services_asset_id ON services(asset_id);
CREATE INDEX idx_deployments_service_observed ON deployments(service_id, observed_at);
CREATE INDEX idx_component_instances_component ON component_instances(component_id);
CREATE INDEX idx_component_instances_project ON component_instances(project_id);
CREATE INDEX idx_findings_status_severity ON findings(status, severity);
CREATE INDEX idx_findings_advisory ON findings(advisory_id);
CREATE INDEX idx_finding_evidence_finding ON finding_evidence(finding_id);
CREATE INDEX idx_scan_runs_started ON scan_runs(started_at DESC);
CREATE INDEX idx_remediations_finding ON remediations(finding_id);
CREATE INDEX idx_ai_runs_provider_started ON ai_runs(provider_id, started_at DESC);
CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp DESC);
