CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    service VARCHAR(32) NOT NULL,
    source_ip INET NOT NULL,
    source_port INTEGER,
    mac_address VARCHAR(17),
    action VARCHAR(64) NOT NULL,
    username TEXT,
    password TEXT,
    data JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dispatched BOOLEAN NOT NULL DEFAULT FALSE,
    dispatched_at TIMESTAMPTZ
);

CREATE INDEX idx_events_pending ON events (created_at) WHERE dispatched = FALSE;
CREATE INDEX idx_events_created_at ON events (created_at DESC);
CREATE INDEX idx_events_service ON events (service);
CREATE INDEX idx_events_source_ip ON events (source_ip);
