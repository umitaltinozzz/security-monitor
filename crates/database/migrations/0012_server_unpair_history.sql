ALTER TABLE assets ADD COLUMN removed_at TEXT;

UPDATE app_metadata SET schema_version = 12 WHERE singleton = 1;
