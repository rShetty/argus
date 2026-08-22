-- Agent identities (phase 2): non-interactive machine principals.
-- Each agent is owned by a human, has bounded scopes, a hashed secret,
-- and can be revoked instantly (kill switch via status + introspection).
CREATE TABLE IF NOT EXISTS agents (
    id            TEXT PRIMARY KEY,               -- agt_<random>
    owner_user_id TEXT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL,
    secret_hash   TEXT NOT NULL,                  -- argon2id
    scopes        TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active', -- active | revoked
    created_at    INTEGER NOT NULL,
    last_seen     INTEGER,
    metadata      TEXT NOT NULL DEFAULT '{}'      -- json: service, env, etc.
);
CREATE INDEX IF NOT EXISTS idx_agents_owner ON agents(owner_user_id);

-- System owner for machine-minted identities (created via /api/admin/agents/mint)
INSERT OR IGNORE INTO users (id,email,name,password_hash,is_admin,created_at)
VALUES ('usr_system','system@argus.local','Argus System',NULL,1,0);
