CREATE TABLE notification_delivery_states_backup AS SELECT * FROM notification_delivery_states;
DROP TABLE notification_delivery_states;

CREATE TABLE notification_channels_new (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    kind TEXT NOT NULL CHECK (kind IN ('desktop', 'webhook', 'slack', 'discord', 'ntfy', 'smtp')),
    config_ref TEXT,
    min_priority INTEGER NOT NULL CHECK (min_priority BETWEEN 0 AND 100),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    network_approved_at TEXT,
    network_approved_destination TEXT
);

INSERT INTO notification_channels_new (
    id, kind, config_ref, min_priority, enabled, created_at, updated_at, record_json,
    network_approved_at, network_approved_destination
)
SELECT
    id, kind, config_ref, min_priority, enabled, created_at, updated_at, record_json,
    network_approved_at, network_approved_destination
FROM notification_channels;

DROP TABLE notification_channels;
ALTER TABLE notification_channels_new RENAME TO notification_channels;

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

INSERT INTO notification_delivery_states (
    id, channel_id, event_fingerprint, last_delivered_at, snoozed_until, lease_expires_at,
    created_at, updated_at, record_json
)
SELECT
    id, channel_id, event_fingerprint, last_delivered_at, snoozed_until, lease_expires_at,
    created_at, updated_at, record_json
FROM notification_delivery_states_backup;

DROP TABLE notification_delivery_states_backup;
CREATE INDEX idx_notification_delivery_channel ON notification_delivery_states(channel_id);

UPDATE app_metadata SET schema_version = 18 WHERE singleton = 1;
