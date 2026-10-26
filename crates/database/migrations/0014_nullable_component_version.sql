ALTER TABLE components RENAME COLUMN version TO legacy_version;
ALTER TABLE components ADD COLUMN version TEXT
    CHECK (version IS NULL OR length(version) > 0);

UPDATE components SET version = NULLIF(legacy_version, '');

UPDATE app_metadata SET schema_version = 14 WHERE singleton = 1;
