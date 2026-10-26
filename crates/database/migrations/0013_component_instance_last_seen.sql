ALTER TABLE component_instances ADD COLUMN last_seen_at TEXT;

UPDATE app_metadata SET schema_version = 13 WHERE singleton = 1;
