CREATE TABLE project_server_links (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    confirmed_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    UNIQUE (project_id, asset_id)
);

CREATE INDEX idx_project_server_links_asset ON project_server_links(asset_id);

UPDATE app_metadata SET schema_version = 10 WHERE singleton = 1;
