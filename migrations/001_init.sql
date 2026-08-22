-- Argus identity store (v1)
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    password_hash TEXT,                -- NULL for GitHub-only accounts
    github_id     TEXT UNIQUE,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS auth_codes (
    code                TEXT PRIMARY KEY,
    client_id           TEXT NOT NULL,
    redirect_uri        TEXT NOT NULL,
    scope               TEXT NOT NULL,
    user_id             TEXT NOT NULL REFERENCES users(id),
    code_challenge      TEXT,
    code_challenge_meth TEXT,
    nonce               TEXT,
    issued_at           INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    used                INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS clients (
    client_id     TEXT PRIMARY KEY,
    secret_hash   TEXT,                 -- NULL for public (SPA) clients
    name          TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,        -- newline-separated exact matches
    scopes        TEXT NOT NULL DEFAULT 'openid profile',
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS consent (
    user_id   TEXT NOT NULL REFERENCES users(id),
    client_id TEXT NOT NULL,
    scope     TEXT NOT NULL,
    decision  TEXT NOT NULL CHECK(decision IN ('approved','denied')),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, client_id, scope)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    client_id  TEXT NOT NULL,
    scope      TEXT NOT NULL,
    issued_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    rotated_to TEXT                    -- refresh-token rotation chain
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         INTEGER NOT NULL,
    event      TEXT NOT NULL,
    user_id    TEXT,
    detail     TEXT NOT NULL DEFAULT '{}'
);
