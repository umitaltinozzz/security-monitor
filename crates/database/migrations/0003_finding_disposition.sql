ALTER TABLE findings ADD COLUMN disposition TEXT
    CHECK (disposition IS NULL OR (json_valid(disposition) AND json_type(disposition) = 'object'));

UPDATE findings
SET status = 'needs_review',
    risk_expires_at = NULL,
    disposition = NULL,
    record_json = json_set(
        record_json,
        '$.status', 'needs_review',
        '$.disposition', NULL,
        '$.risk_expires_at', NULL
    )
WHERE status IN ('not_reachable', 'accepted_risk', 'false_positive')
  AND disposition IS NULL;

UPDATE app_metadata SET schema_version = 3 WHERE singleton = 1;
