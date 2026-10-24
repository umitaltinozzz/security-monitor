CREATE TABLE ai_transfer_approvals (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
    provider_id TEXT NOT NULL REFERENCES ai_providers(id) ON DELETE RESTRICT,
    destination_origin TEXT NOT NULL CHECK (length(destination_origin) > 0),
    data_category TEXT NOT NULL CHECK (data_category IN ('advisory_metadata', 'source_code', 'inventory', 'user_prompt')),
    tier TEXT NOT NULL CHECK (tier IN ('triage', 'analysis', 'patch')),
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'),
    approved_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);
CREATE INDEX idx_ai_transfer_approvals_time ON ai_transfer_approvals(approved_at DESC);
UPDATE app_metadata SET schema_version = 6 WHERE singleton = 1;
