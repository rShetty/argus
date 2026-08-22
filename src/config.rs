use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub database: String,
    /// Base URL users hit in the browser — used to build authorize URLs.
    pub external_url: String,
    /// Signing material. Generate once:
    ///   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | ...
    /// v1 accepts a PEM file path; rotation = swap file + keep old in JWKS.
    #[serde(default)]
    pub signing_key_pem_path: Option<String>,
    /// Access-token lifetime (seconds).
    #[serde(default = "default_access_ttl")]
    pub access_token_ttl: u64,
    /// Session cookie lifetime (seconds).
    #[serde(default = "default_session_ttl")]
    pub session_ttl: u64,
    /// GitHub OAuth app credentials (env overrides).
    #[serde(default)]
    pub github_client_id: Option<String>,
    #[serde(default)]
    pub github_client_secret: Option<String>,
    /// Bootstrap admin, promoted on first login only.
    #[serde(default)]
    pub bootstrap_admin_email: Option<String>,
}

fn default_listen() -> String {
    "127.0.0.1:8443".into()
}
fn default_access_ttl() -> u64 {
    3600
}
fn default_session_ttl() -> u64 {
    12 * 3600
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let mut cfg: Config = toml::from_str(&raw)?;
        if let Ok(id) = std::env::var("GITHUB_CLIENT_ID") {
            cfg.github_client_id = Some(id);
        }
        if let Ok(s) = std::env::var("GITHUB_CLIENT_SECRET") {
            cfg.github_client_secret = Some(s);
        }
        Ok(cfg)
    }
}
