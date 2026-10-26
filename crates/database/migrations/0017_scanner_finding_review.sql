ALTER TABLE scanner_findings
ADD COLUMN review_status TEXT NOT NULL DEFAULT 'needs_review'
CHECK (review_status IN ('needs_review', 'confirmed', 'accepted_risk', 'false_positive', 'resolved'));

ALTER TABLE scanner_findings
ADD COLUMN review_reason TEXT
CHECK (review_reason IS NULL OR length(trim(review_reason)) BETWEEN 1 AND 1000);

ALTER TABLE scanner_findings
ADD COLUMN reviewed_at TEXT;

UPDATE app_metadata SET schema_version = 17 WHERE singleton = 1;
