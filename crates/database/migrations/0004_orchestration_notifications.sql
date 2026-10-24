ALTER TABLE notification_channels ADD COLUMN network_approved_at TEXT;
ALTER TABLE notification_channels ADD COLUMN network_approved_destination TEXT;

CREATE TABLE project_scan_checkpoints (
    id TEXT PRIMARY KEY NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
    input_hash TEXT CHECK (
        input_hash IS NULL OR
        (length(input_hash) = 64 AND input_hash NOT GLOB '*[^0-9a-f]*')
    ),
    inventory_json TEXT NOT NULL CHECK (json_valid(inventory_json)),
    inventory_complete INTEGER NOT NULL CHECK (inventory_complete IN (0, 1)),
    checked_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json))
);

CREATE TABLE notification_delivery_states (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    channel_id TEXT NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    event_fingerprint TEXT NOT NULL CHECK (length(event_fingerprint) > 0),
    last_delivered_at TEXT,
    snoozed_until TEXT,
    lease_expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    UNIQUE(channel_id, event_fingerprint)
);

CREATE INDEX idx_notification_delivery_channel ON notification_delivery_states(channel_id);

UPDATE app_metadata SET schema_version = 4 WHERE singleton = 1;
