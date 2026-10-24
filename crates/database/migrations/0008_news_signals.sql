CREATE TABLE news_signals (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    feed_id TEXT NOT NULL CHECK (length(feed_id) > 0),
    external_id TEXT NOT NULL CHECK (length(external_id) > 0),
    advisory_id TEXT,
    archived_at TEXT,
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    UNIQUE (feed_id, external_id)
);

UPDATE app_metadata SET schema_version = 8 WHERE singleton = 1;
