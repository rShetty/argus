pub mod config;
pub mod crypto;
pub mod routes;
pub mod store;
pub mod tokens;

use axum::routing::{get, post};
use axum::Router;
pub use config::Config;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<store::Store>,
    pub key: Arc<crypto::SigningKey>,
    pub http: reqwest::Client,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        // OIDC discovery
        .route("/.well-known/openid-configuration", get(routes::discovery))
        .route("/jwks.json", get(routes::jwks))
        // Interactive login
        // Landing page — logged-in users get a profile view, everyone else
        // is sent to /login. Prevents 404s on bare id.rajeev.me visits.
        .route("/", get(routes::index))
        .route("/login", get(routes::login_form).post(routes::login_submit))
        .route("/session/check", get(routes::session_check))
        .route("/logout", post(routes::logout).get(routes::logout_get))
        .route(
            "/register",
            get(routes::register_form).post(routes::register_submit),
        )
        .route(
            "/forgot-password",
            get(routes::forgot_password_form).post(routes::forgot_password_submit),
        )
        .route(
            "/reset-password",
            get(routes::reset_password_form).post(routes::reset_password_submit),
        )
        // GitHub OAuth upstream
        .route("/auth/github", get(routes::github_start))
        .route("/auth/github/callback", get(routes::github_callback))
        // Authorization endpoint (consent)
        .route(
            "/authorize",
            get(routes::authorize).post(routes::authorize_consent),
        )
        // Token endpoints
        .route("/token", post(routes::token))
        .route("/userinfo", get(routes::userinfo))
        .route("/introspect", post(routes::introspect))
        // Agent identities (phase 2)
        .route(
            "/api/agents",
            get(routes::agents_list).post(routes::agents_create),
        )
        .route("/api/agents/{id}/status", post(routes::agents_set_status))
        // Admin directory + client registry
        .route("/api/admin/users", get(routes::admin_users))
        .route(
            "/api/admin/users/{id}/status",
            post(routes::admin_set_user_status),
        )
        .route("/api/admin/agents", get(routes::admin_agents))
        .route(
            "/api/admin/agents/{id}/revoke",
            post(routes::admin_revoke_agent),
        )
        .route("/api/admin/agents/mint", post(routes::agents_mint))
        .route("/api/admin/clients", post(routes::admin_create_client))
        // Ops
        .route("/health", get(routes::health))
        .layer(axum::middleware::map_response(
            |mut res: axum::response::Response| async move {
                let h = res.headers_mut();
                h.insert("x-frame-options", "DENY".parse().unwrap());
                h.insert("x-content-type-options", "nosniff".parse().unwrap());
                h.insert("referrer-policy", "no-referrer".parse().unwrap());
                if let Ok(v) = "max-age=63072000; includeSubDomains; preload".parse() {
                    h.insert("strict-transport-security", v);
                }
                res
            },
        ))
        .with_state(state)
}

// ── Cookie security policy ───────────────────────────────────────────────────
// Secure attribute is correct for https deployments; http local/dev must omit
// it or cookies are silently dropped by HTTP clients.

use std::sync::OnceLock;
static COOKIE_SECURE: OnceLock<bool> = OnceLock::new();

pub fn init_cookie_secure(external_url: &str) {
    let _ = COOKIE_SECURE.set(external_url.starts_with("https"));
}

pub fn cookie_secure() -> bool {
    *COOKIE_SECURE.get().unwrap_or(&true)
}
