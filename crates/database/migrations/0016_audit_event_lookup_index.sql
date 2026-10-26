CREATE INDEX idx_audit_events_lookup
    ON audit_events(action, result, json_extract(scope_json, '$.resource_id'), timestamp DESC);

UPDATE app_metadata SET schema_version = 16 WHERE singleton = 1;
