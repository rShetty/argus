use argus::{router, AppState, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "argus=info".into()),
        )
        .init();

    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/argus/argus.toml".to_string());
    let cfg = Config::load(&path)?;
    let listen = cfg.listen.clone();
    let external_url = cfg.external_url.clone();
    argus::init_cookie_secure(&external_url);

    let db_path = if cfg.database.is_empty() {
        "/var/lib/argus/argus.db".to_string()
    } else {
        cfg.database.clone()
    };
    let state = AppState {
        config: std::sync::Arc::new(cfg),
        store: std::sync::Arc::new(argus::store::Store::open(&db_path)?),
        key: std::sync::Arc::new(argus::crypto::SigningKey::load_or_create(
            None, // default location under db dir
        )?),
        http: reqwest::Client::new(),
    };

    tracing::info!("argus IdP listening on {listen} (issuer {external_url})");
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}
