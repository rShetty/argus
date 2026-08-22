//! SQLite persistence layer (rusqlite, spawn_blocking-wrapped by callers).

use anyhow::Context;
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(db_path: &str) -> anyhow::Result<Self> {
        if let Some(parent) = Path::new(db_path).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(db_path).context("open sqlite db")?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "foreign_keys", "ON").ok();
        let s = Self {
            conn: Mutex::new(conn),
        };
        s.migrate()?;
        Ok(s)
    }

    pub fn with_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let conn = self.conn.lock().unwrap();
        f(&conn)
    }

    fn migrate(&self) -> anyhow::Result<()> {
        const M001: &str = include_str!("../migrations/001_init.sql");
        const M002: &str = include_str!("../migrations/002_agents.sql");
        self.with_conn(|c| {
            c.execute_batch(M001)?;
            c.execute_batch(M002)?;
            Ok(())
        })
    }
}

// ---- Typed rows -------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    #[allow(dead_code)]
    pub password_hash: Option<String>,
    #[allow(dead_code)]
    pub github_id: Option<String>,
    pub is_admin: bool,
    #[allow(dead_code)]
    pub disabled: bool,
}

fn row_to_user(row: &rusqlite::Row) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        email: row.get(1)?,
        name: row.get(2)?,
        password_hash: row.get(3)?,
        github_id: row.get(4)?,
        is_admin: row.get::<_, i64>(5)? != 0,
        disabled: row.get::<_, i64>(6)? != 0,
    })
}

const USER_COLS: &str = "id, email, name, password_hash, github_id, is_admin, disabled";

impl Store {
    pub fn user_by_email(&self, email: &str) -> anyhow::Result<Option<User>> {
        self.with_conn(|c| {
            let mut st = c.prepare(&format!("SELECT {USER_COLS} FROM users WHERE email = ?1"))?;
            let mut rows = st.query([email])?;
            Ok(match rows.next()? {
                Some(r) => Some(row_to_user(r)?),
                None => None,
            })
        })
    }

    pub fn user_by_id(&self, id: &str) -> anyhow::Result<Option<User>> {
        self.with_conn(|c| {
            let mut st = c.prepare(&format!("SELECT {USER_COLS} FROM users WHERE id = ?1"))?;
            let mut rows = st.query([id])?;
            Ok(match rows.next()? {
                Some(r) => Some(row_to_user(r)?),
                None => None,
            })
        })
    }

    pub fn user_by_github_id(&self, gh_id: &str) -> anyhow::Result<Option<User>> {
        self.with_conn(|c| {
            let mut st = c.prepare(&format!(
                "SELECT {USER_COLS} FROM users WHERE github_id = ?1"
            ))?;
            let mut rows = st.query([gh_id])?;
            Ok(match rows.next()? {
                Some(r) => Some(row_to_user(r)?),
                None => None,
            })
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_user(
        &self,
        id: &str,
        email: &str,
        name: &str,
        password_hash: Option<&str>,
        github_id: Option<&str>,
        is_admin: bool,
    ) -> anyhow::Result<()> {
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO users (id,email,name,password_hash,github_id,is_admin,created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)",
                rusqlite::params![
                    id,
                    email,
                    name,
                    password_hash,
                    github_id,
                    is_admin as i64,
                    tokens_now()
                ],
            )?;
            Ok(())
        })
    }

    pub fn set_password_hash(&self, user_id: &str, hash: Option<&str>) -> anyhow::Result<()> {
        self.with_conn(|c| {
            c.execute(
                "UPDATE users SET password_hash=?2 WHERE id=?1",
                rusqlite::params![user_id, hash],
            )?;
            Ok(())
        })
    }

    // ---- sessions ----
    pub fn create_session(
        &self,
        id: &str,
        user_id: &str,
        ttl: u64,
        ip: &str,
    ) -> anyhow::Result<()> {
        let now = tokens_now();
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO sessions (id,user_id,created_at,expires_at,ip) VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![id, user_id, now, now + ttl, ip],
            )?;
            Ok(())
        })
    }

    pub fn session_user(&self, sid: &str) -> anyhow::Result<Option<User>> {
        let now = tokens_now();
        self.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT u.id, u.email, u.name, u.password_hash, u.github_id, u.is_admin, u.disabled \
                 FROM users u JOIN sessions s ON s.user_id=u.id \
                 WHERE s.id=?1 AND s.expires_at > ?2 AND u.disabled=0",
            )?;
            let mut rows = st.query(rusqlite::params![sid, now])?;
            Ok(match rows.next()? {
                Some(r) => Some(row_to_user(r)?),
                None => None,
            })
        })
    }

    pub fn delete_session(&self, sid: &str) -> anyhow::Result<()> {
        self.with_conn(|c| {
            c.execute("DELETE FROM sessions WHERE id=?1", [sid])?;
            Ok(())
        })?;
        Ok(())
    }

    // ---- clients ----
    pub fn struct_client_row(row: &rusqlite::Row) -> rusqlite::Result<Client> {
        Ok(Client {
            client_id: row.get(0)?,
            secret_hash: row.get(1)?,
            name: row.get(2)?,
            redirect_uris: row
                .get::<_, String>(3)?
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            scopes: row.get(4)?,
        })
    }

    pub fn client(&self, client_id: &str) -> anyhow::Result<Option<Client>> {
        self.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT client_id, secret_hash, name, redirect_uris, scopes FROM clients WHERE client_id=?1",
            )?;
            let mut rows = st.query([client_id])?;
            Ok(match rows.next()? {
                Some(r) => Some(Self::struct_client_row(r)?),
                None => None,
            })
        })
    }

    // ---- auth codes ----
    #[allow(clippy::too_many_arguments)]
    pub fn put_auth_code(&self, code: &AuthCode) -> anyhow::Result<()> {
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO auth_codes (code,client_id,redirect_uri,scope,user_id,code_challenge,code_challenge_meth,nonce,issued_at,expires_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                rusqlite::params![
                    code.code,
                    code.client_id,
                    code.redirect_uri,
                    code.scope,
                    code.user_id,
                    code.code_challenge,
                    code.code_challenge_meth,
                    code.nonce,
                    code.issued_at,
                    code.expires_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn take_auth_code(&self, code: &str) -> anyhow::Result<Option<AuthCode>> {
        let now = tokens_now();
        self.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT code,client_id,redirect_uri,scope,user_id,code_challenge,code_challenge_meth,nonce,issued_at,expires_at \
                 FROM auth_codes WHERE code=?1 AND used=0 AND expires_at>?2",
            )?;
            let mut rows = st.query(rusqlite::params![code, now])?;
            let ac = match rows.next()? {
                Some(r) => Some(AuthCode {
                    code: r.get(0)?,
                    client_id: r.get(1)?,
                    redirect_uri: r.get(2)?,
                    scope: r.get(3)?,
                    user_id: r.get(4)?,
                    code_challenge: r.get(5)?,
                    code_challenge_meth: r.get(6)?,
                    nonce: r.get(7)?,
                    issued_at: r.get(8)?,
                    expires_at: r.get(9)?,
                }),
                None => None,
            };
            if ac.is_some() {
                c.execute("UPDATE auth_codes SET used=1 WHERE code=?1", [code])?;
            }
            Ok(ac)
        })
    }

    // ---- consent ----
    pub fn consent(
        &self,
        user_id: &str,
        client_id: &str,
        scope: &str,
    ) -> anyhow::Result<Option<String>> {
        self.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT decision FROM consent WHERE user_id=?1 AND client_id=?2 AND scope=?3",
            )?;
            let mut rows = st.query(rusqlite::params![user_id, client_id, scope])?;
            Ok(rows.next()?.map(|r| r.get(0)).transpose()?)
        })
    }

    pub fn save_consent(
        &self,
        user_id: &str,
        client_id: &str,
        scope: &str,
        decision: &str,
    ) -> anyhow::Result<()> {
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO consent (user_id,client_id,scope,decision,updated_at) VALUES (?1,?2,?3,?4,?5) \
                 ON CONFLICT(user_id,client_id,scope) DO UPDATE SET decision=excluded.decision, updated_at=excluded.updated_at",
                rusqlite::params![user_id, client_id, scope, decision, tokens_now()],
            )?;
            Ok(())
        })
    }

    // ---- refresh tokens ----
    pub fn put_refresh(
        &self,
        token: &str,
        user_id: &str,
        client_id: &str,
        scope: &str,
        ttl: u64,
    ) -> anyhow::Result<()> {
        let now = tokens_now();
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO refresh_tokens (token,user_id,client_id,scope,issued_at,expires_at) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![token, user_id, client_id, scope, now, now + ttl],
            )?;
            Ok(())
        })
    }

    /// Consume a refresh token (rotation): mark it rotated and return its data.
    pub fn rotate_refresh(
        &self,
        token: &str,
        replacement: &str,
    ) -> anyhow::Result<Option<(String, String, String)>> {
        let now = tokens_now();
        self.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT user_id,client_id,scope FROM refresh_tokens WHERE token=?1 AND expires_at>?2 AND rotated_to IS NULL",
            )?;
            let mut rows = st.query(rusqlite::params![token, now])?;
            let data = match rows.next()? {
                Some(r) => (r.get(0)?, r.get(1)?, r.get(2)?),
                None => return Ok(None),
            };
            c.execute(
                "UPDATE refresh_tokens SET rotated_to=?2 WHERE token=?1",
                rusqlite::params![token, replacement],
            )?;
            Ok(Some(data))
        })
    }

    pub fn audit(
        &self,
        event: &str,
        user_id: Option<&str>,
        detail: serde_json::Value,
    ) -> anyhow::Result<()> {
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO audit_log (at,event,user_id,detail) VALUES (?1,?2,?3,?4)",
                rusqlite::params![tokens_now(), event, user_id, detail.to_string()],
            )?;
            Ok(())
        })
    }
}

#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    #[allow(dead_code)]
    pub secret_hash: Option<String>,
    pub name: String,
    pub redirect_uris: Vec<String>,
    #[allow(dead_code)]
    pub scopes: String,
}

#[derive(Debug, Clone)]
pub struct AuthCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub user_id: String,
    pub code_challenge: Option<String>,
    pub code_challenge_meth: Option<String>,
    pub nonce: Option<String>,
    #[allow(dead_code)]
    pub issued_at: u64,
    pub expires_at: u64,
}

pub fn tokens_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---- Agent identities (phase 2) ---------------------------------------------

#[derive(Debug, Clone)]
pub struct Agent {
    pub id: String,
    pub owner_user_id: String,
    pub name: String,
    #[allow(dead_code)]
    pub secret_hash: String,
    pub scopes: Vec<String>,
    pub status: String,
    #[allow(dead_code)]
    pub created_at: u64,
}

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub fn create_agent(
        &self,
        id: &str,
        owner_user_id: &str,
        name: &str,
        secret_hash: &str,
        scopes: &[String],
        metadata: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO agents (id,owner_user_id,name,secret_hash,scopes,status,created_at,metadata)
                 VALUES (?1,?2,?3,?4,?5,'active',?6,?7)",
                rusqlite::params![
                    id,
                    owner_user_id,
                    name,
                    secret_hash,
                    scopes.join(" "),
                    tokens_now(),
                    metadata.to_string(),
                ],
            )?;
            Ok(())
        })
    }

    pub fn agent_by_id(&self, id: &str) -> anyhow::Result<Option<Agent>> {
        self.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT id,owner_user_id,name,secret_hash,scopes,status,created_at FROM agents WHERE id=?1",
            )?;
            let mut rows = st.query([id])?;
            Ok(match rows.next()? {
                Some(r) => Some(Agent {
                    id: r.get(0)?,
                    owner_user_id: r.get(1)?,
                    name: r.get(2)?,
                    secret_hash: r.get(3)?,
                    scopes: r.get::<_, String>(4)?
                        .split(' ')
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect(),
                    status: r.get(5)?,
                    created_at: r.get(6)?,
                }),
                None => None,
            })
        })
    }

    pub fn agents_for_owner(&self, owner_user_id: &str) -> anyhow::Result<Vec<Agent>> {
        self.with_conn(|c| {
            let mut st = c.prepare(
                "SELECT id,owner_user_id,name,secret_hash,scopes,status,created_at FROM agents WHERE owner_user_id=?1 ORDER BY created_at",
            )?;
            let rows = st.query_map([owner_user_id], |r| {
                Ok(Agent {
                    id: r.get(0)?,
                    owner_user_id: r.get(1)?,
                    name: r.get(2)?,
                    secret_hash: r.get(3)?,
                    scopes: r.get::<_, String>(4)?
                        .split(' ')
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect(),
                    status: r.get(5)?,
                    created_at: r.get(6)?,
                })
            })?;
            Ok(rows.filter_map(Result::ok).collect())
        })
    }

    /// Kill switch — introspection refuses revoked agents immediately.
    pub fn set_agent_status(&self, id: &str, owner: &str, status: &str) -> anyhow::Result<bool> {
        self.with_conn(|c| {
            let n = c.execute(
                "UPDATE agents SET status=?3 WHERE id=?1 AND owner_user_id=?2",
                rusqlite::params![id, owner, status],
            )?;
            Ok(n > 0)
        })
    }

    pub fn touch_agent(&self, id: &str) -> anyhow::Result<()> {
        self.with_conn(|c| {
            c.execute(
                "UPDATE agents SET last_seen=?2 WHERE id=?1",
                rusqlite::params![id, tokens_now()],
            )?;
            Ok(())
        })
    }
}
