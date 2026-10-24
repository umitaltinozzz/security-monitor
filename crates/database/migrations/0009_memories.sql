CREATE TABLE memories (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    scope TEXT NOT NULL CHECK (scope IN ('global', 'project', 'server', 'finding')),
    scope_id TEXT,
    kind TEXT NOT NULL CHECK (kind IN ('finding_note', 'user_decision', 'project_context', 'failed_fix', 'agent_summary')),
    content TEXT NOT NULL CHECK (length(content) BETWEEN 1 AND 8192),
    author TEXT NOT NULL CHECK (length(author) BETWEEN 1 AND 96),
    source_run_id TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    pinned INTEGER NOT NULL CHECK (pinned IN (0, 1)),
    verified_at TEXT,
    verified_by TEXT CHECK (verified_by IS NULL OR verified_by = 'user'),
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    CHECK ((scope = 'global' AND scope_id IS NULL) OR (scope <> 'global' AND scope_id IS NOT NULL AND length(scope_id) > 0))
);

CREATE INDEX idx_memories_scope_expiry_pinned ON memories(scope, scope_id, expires_at, pinned, created_at DESC);
CREATE INDEX idx_memories_author ON memories(author, created_at DESC);

UPDATE app_metadata SET schema_version = 9 WHERE singleton = 1;
