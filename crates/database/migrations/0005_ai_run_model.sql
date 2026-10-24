ALTER TABLE ai_runs ADD COLUMN model TEXT NOT NULL DEFAULT '';
UPDATE app_metadata SET schema_version = 5 WHERE singleton = 1;
