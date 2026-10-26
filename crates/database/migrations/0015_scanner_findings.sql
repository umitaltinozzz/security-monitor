CREATE TABLE scanner_findings (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    scanner TEXT NOT NULL CHECK (scanner IN ('osv-scanner', 'trivy', 'semgrep')),
    mode TEXT NOT NULL CHECK (mode IN ('dependencies', 'filesystem', 'misconfiguration', 'image_archive', 'code')),
    kind TEXT NOT NULL CHECK (kind IN ('vulnerability', 'secret', 'misconfiguration', 'code')),
    rule_id TEXT,
    aliases TEXT NOT NULL CHECK (json_valid(aliases) AND json_type(aliases) = 'array'),
    package_name TEXT,
    package_ecosystem TEXT,
    package_version TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    title TEXT,
    fixed_version TEXT,
    path TEXT,
    line_start INTEGER CHECK (line_start IS NULL OR line_start > 0),
    line_end INTEGER CHECK (line_end IS NULL OR line_end > 0),
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    CHECK (line_start IS NULL OR line_end IS NULL OR line_end >= line_start),
    UNIQUE (project_id, scanner, mode, fingerprint)
);

CREATE INDEX scanner_findings_project_last_seen ON scanner_findings(project_id, last_seen_at DESC);

UPDATE app_metadata SET schema_version = 15 WHERE singleton = 1;
