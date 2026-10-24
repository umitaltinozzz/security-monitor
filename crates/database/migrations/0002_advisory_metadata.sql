ALTER TABLE advisories ADD COLUMN title TEXT NOT NULL DEFAULT '';
ALTER TABLE advisories ADD COLUMN summary TEXT;
ALTER TABLE advisories ADD COLUMN summary_model TEXT;
ALTER TABLE advisories ADD COLUMN description TEXT;
ALTER TABLE advisories ADD COLUMN source_attributions TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(source_attributions) AND json_type(source_attributions) = 'array');

UPDATE app_metadata SET schema_version = 2 WHERE singleton = 1;
