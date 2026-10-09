CREATE TABLE api_tokens (
			id         TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL REFERENCES users(id),
			name       TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			prefix     TEXT NOT NULL,
			scopes     TEXT NOT NULL DEFAULT '[]',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			expires_at TEXT DEFAULT '',
			last_used  TEXT DEFAULT ''
		);
CREATE TABLE invites (
			id          TEXT PRIMARY KEY,
			token_hash  TEXT UNIQUE NOT NULL,
			prefix      TEXT NOT NULL,
			created_by  TEXT NOT NULL DEFAULT '',
			role        TEXT NOT NULL DEFAULT 'user',
			max_uses    INTEGER NOT NULL DEFAULT 1,
			use_count   INTEGER NOT NULL DEFAULT 0,
			expires_at  TEXT NOT NULL,
			revoked_at  TEXT NOT NULL DEFAULT '',
			created_at  TEXT NOT NULL
		, tenant_id TEXT NOT NULL DEFAULT '');
CREATE TABLE sessions (
			token      TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL REFERENCES users(id),
			kind       TEXT NOT NULL DEFAULT 'full',
			created_at TEXT NOT NULL DEFAULT (datetime('now')),
			expires_at TEXT NOT NULL
		);
CREATE TABLE totp (
			user_id     TEXT PRIMARY KEY REFERENCES users(id),
			secret      TEXT NOT NULL,
			enabled     INTEGER NOT NULL DEFAULT 1,
			verified_at TEXT DEFAULT '',
			created_at  TEXT NOT NULL DEFAULT (datetime('now'))
		);
CREATE TABLE users (
			id         TEXT PRIMARY KEY,
			username   TEXT UNIQUE NOT NULL,
			password   TEXT NOT NULL,
			roles      TEXT NOT NULL DEFAULT '[]',
			totp_secret TEXT DEFAULT '',
			totp_enabled INTEGER DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		, tenant_id TEXT NOT NULL DEFAULT '');
CREATE TABLE webauthn_credentials (
			id              TEXT PRIMARY KEY,
			user_id         TEXT NOT NULL REFERENCES users(id),
			public_key      BLOB NOT NULL,
			credential_type TEXT NOT NULL DEFAULT 'public-key',
			transports      TEXT DEFAULT '[]',
			aaguid          TEXT DEFAULT '',
			sign_count      INTEGER DEFAULT 0,
			created_at      TEXT NOT NULL DEFAULT (datetime('now')),
			last_used_at    TEXT DEFAULT ''
		);
CREATE TABLE webauthn_sessions (
			challenge   TEXT PRIMARY KEY,
			user_id     TEXT NOT NULL,
			data        BLOB NOT NULL,
			expires_at  TEXT NOT NULL
		);
CREATE INDEX idx_api_tokens_user ON api_tokens(user_id);
CREATE INDEX idx_invites_hash ON invites(token_hash);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_webauthn_user ON webauthn_credentials(user_id);
