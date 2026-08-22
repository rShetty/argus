//! Interactive + protocol routes. HTML is deliberately minimal/inline —
//! no external assets, CSP-friendly.

use crate::{tokens, AppState};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use serde::Deserialize;
use serde_json::json;

const SESSION_COOKIE: &str = "argus_session";
const CSRF_COOKIE: &str = "argus_csrf";
const GH_STATE_COOKIE: &str = "argus_gh_state";
const GH_NEXT_COOKIE: &str = "argus_gh_next";

fn now() -> u64 {
    tokens::now_epoch()
}

fn rand_token(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    crate::crypto::b64url(&buf)
}

fn append_cookie(resp: &mut Response, value: String) {
    resp.headers_mut()
        .append(header::SET_COOKIE, value.parse().unwrap());
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn csrf_ok(headers: &HeaderMap, submitted: &str) -> bool {
    let Some(cookie_token) = cookie_value(headers, CSRF_COOKIE) else {
        return false;
    };
    !cookie_token.is_empty()
        && cookie_token.len() <= 128
        && ct_eq(cookie_token.as_bytes(), submitted.as_bytes())
}

async fn current_user(state: &AppState, headers: &HeaderMap) -> Option<crate::store::User> {
    let sid = cookie_value(headers, SESSION_COOKIE)?;
    state.store.session_user(&sid).ok().flatten()
}

fn ensure_csrf_cookie(headers: &HeaderMap) -> String {
    let existing = cookie_value(headers, CSRF_COOKIE).unwrap_or_default();
    if existing.len().between(1, 128) {
        existing
    } else {
        rand_token(32)
    }
}

trait Between {
    fn between(&self, lo: usize, hi: usize) -> bool;
}
impl Between for usize {
    fn between(&self, lo: usize, hi: usize) -> bool {
        *self >= lo && *self <= hi
    }
}

/// Only local paths survive; never an off-site redirect.
fn safe_next(next: &str) -> String {
    if next.starts_with('/') && !next.starts_with("//") && !next.contains('\\') {
        next.to_string()
    } else {
        "/".to_string()
    }
}

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title} — Argus</title>\
         <style>body{{font-family:system-ui,sans-serif;background:#0b1020;color:#e5e7eb;\
         display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}\
         .card{{background:#111a33;padding:2rem;border-radius:12px;width:22rem}}\
         h1{{font-size:1.1rem;margin-top:0}}input,button{{width:100%;box-sizing:border-box;\
         padding:.6rem;margin:.3rem 0;border-radius:8px;border:1px solid #334155;\
         background:#0b1020;color:inherit}}button{{background:#6366f1;border:none;cursor:pointer;\
         font-weight:600}}a{{color:#818cf8}}.gh{{background:#24292f}}</style></head>\
         <body><div class=\"card\"><h1>Argus — {title}</h1>{body}</div></body></html>"
    ))
}

fn err_page(msg: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        page("Error", &format!("<p>{msg}</p><a href=\"/login\">Back</a>")),
    )
        .into_response()
}

fn promote_bootstrap_admin(state: &AppState, email: &str) {
    if state.config.bootstrap_admin_email.as_deref() == Some(email) {
        let _ = state.store.with_conn(|c| {
            c.execute("UPDATE users SET is_admin=1 WHERE email=?1", [email])?;
            Ok(())
        });
    }
}

// ---------------------------------------------------------------------------
// discovery / jwks / health
// ---------------------------------------------------------------------------

pub async fn discovery(State(state): State<AppState>) -> Response {
    let iss = state.config.external_url.trim_end_matches('/');
    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        axum::Json(json!({
            "issuer": iss,
            "authorization_endpoint": format!("{iss}/authorize"),
            "token_endpoint": format!("{iss}/token"),
            "userinfo_endpoint": format!("{iss}/userinfo"),
            "jwks_uri": format!("{iss}/jwks.json"),
            "introspection_endpoint": format!("{iss}/introspect"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["openid", "profile", "email", "offline_access"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
            "claims_supported": ["sub", "email", "name", "iss", "aud", "exp", "iat"],
        })),
    )
        .into_response()
}

pub async fn jwks(State(state): State<AppState>) -> Response {
    (
        [(header::CACHE_CONTROL, "public, max-age=300")],
        axum::Json(json!({"keys": [state.key.jwk()]})),
    )
        .into_response()
}

pub async fn health() -> Response {
    axum::Json(json!({"status": "ok", "service": "argus"})).into_response()
}

// ---------------------------------------------------------------------------
// login / register / logout
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct NextQuery {
    next: Option<String>,
}

pub async fn login_form(
    State(state): State<AppState>,
    Query(q): Query<NextQuery>,
    headers: HeaderMap,
) -> Response {
    let csrf = ensure_csrf_cookie(&headers);
    let next = q.next.unwrap_or_default();
    let gh_enabled = state.config.github_client_id.is_some();
    let n = urlencoding::encode(&next);
    let body = format!(
        "<form method=\"post\" action=\"/login\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"next\" value=\"{n}\">\
         <input type=\"email\" name=\"email\" placeholder=\"Email\" required autofocus>\
         <input type=\"password\" name=\"password\" placeholder=\"Password\" required>\
         <button type=\"submit\">Sign in</button></form>\
         <p style=\"text-align:center\">— or —</p>\
         <form method=\"get\" action=\"/auth/github\">\
         <input type=\"hidden\" name=\"next\" value=\"{n}\">\
         <button class=\"gh\" {}>Sign in with GitHub</button></form>\
         <p style=\"font-size:.8rem;text-align:center\"><a href=\"/register?next={n}\">Create account</a></p>",
        if gh_enabled {
            ""
        } else {
            "disabled title='GitHub login not configured'"
        },
    );
    let mut resp = page("Sign in", &body).into_response();
    append_cookie(
        &mut resp,
        format!("{CSRF_COOKIE}={csrf}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax; Secure"),
    );
    resp
}

#[derive(Deserialize)]
pub struct LoginForm {
    email: String,
    password: String,
    #[serde(default)]
    next: String,
    #[serde(default)]
    csrf: String,
}

pub async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<LoginForm>,
) -> Response {
    if !csrf_ok(&headers, &f.csrf) {
        return err_page("Invalid CSRF token");
    }
    let email = f.email.trim().to_lowercase();
    let user = state.store.user_by_email(&email).ok().flatten();
    let ok = user
        .as_ref()
        .map(|u| {
            !u.disabled
                && u.password_hash
                    .as_deref()
                    .map(|h| crate::crypto::verify_password(&f.password, h))
                    .unwrap_or(false)
        })
        .unwrap_or(false);

    if !ok {
        let _ = state
            .store
            .audit("login_failed", None, json!({"email": email}));
        return (
            StatusCode::UNAUTHORIZED,
            page(
                "Sign in",
                "<p>Invalid email or password.</p><a href=\"/login\">Try again</a>",
            ),
        )
            .into_response();
    }

    let user = user.expect("checked above");
    promote_bootstrap_admin(&state, &user.email);

    let sid = rand_token(32);
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let _ = state
        .store
        .create_session(&sid, &user.id, state.config.session_ttl, &ip);
    let _ = state
        .store
        .audit("login_password", Some(&user.id), json!({}));

    let mut resp = Redirect::to(&safe_next(&f.next)).into_response();
    append_cookie(
        &mut resp,
        format!(
            "{SESSION_COOKIE}={sid}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax; Secure",
            state.config.session_ttl
        ),
    );
    // Rotate CSRF token after auth-state change.
    append_cookie(
        &mut resp,
        format!("{CSRF_COOKIE}=; Path=/; Max-Age=0; HttpOnly"),
    );
    resp
}

#[derive(Deserialize)]
pub struct RegisterQuery {
    next: Option<String>,
}

pub async fn register_form(
    State(_state): State<AppState>,
    Query(q): Query<RegisterQuery>,
    headers: HeaderMap,
) -> Response {
    let csrf = ensure_csrf_cookie(&headers);
    let next_owned = q.next.unwrap_or_default();
    let next = urlencoding::encode(&next_owned);
    let body = format!(
        "<form method=\"post\" action=\"/register\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"next\" value=\"{next}\">\
         <input type=\"text\" name=\"name\" placeholder=\"Name\" required maxlength=\"200\">\
         <input type=\"email\" name=\"email\" placeholder=\"Email\" required>\
         <input type=\"password\" name=\"password\" minlength=\"10\" placeholder=\"Password (min 10 chars)\" required>\
         <button>Create account</button></form>"
    );
    let mut resp = page("Register", &body).into_response();
    append_cookie(
        &mut resp,
        format!("{CSRF_COOKIE}={csrf}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax; Secure"),
    );
    resp
}

#[derive(Deserialize)]
pub struct RegisterForm {
    name: String,
    email: String,
    password: String,
    #[serde(default)]
    next: String,
    #[serde(default)]
    csrf: String,
}

pub async fn register_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<RegisterForm>,
) -> Response {
    if !csrf_ok(&headers, &f.csrf) {
        return err_page("Invalid CSRF token");
    }
    let email = f.email.trim().to_lowercase();
    let name = f.name.trim().to_string();
    if !email.contains('@') || email.len() > 254 || name.is_empty() || name.len() > 200 {
        return err_page("Invalid input");
    }
    if f.password.len() < 10 || f.password.len() > 1024 {
        return err_page("Password must be 10–1024 characters");
    }
    if state.store.user_by_email(&email).ok().flatten().is_some() {
        return err_page("An account with that email already exists");
    }
    let hash = match crate::crypto::hash_password(&f.password) {
        Ok(h) => h,
        Err(_) => return err_page("Internal error"),
    };
    let id = format!("usr_{}", rand_token(16));
    if state
        .store
        .create_user(&id, &email, &name, Some(&hash), None, false)
        .is_err()
    {
        return err_page("Could not create account");
    }
    let _ = state
        .store
        .audit("register", Some(&id), json!({"email": email}));
    promote_bootstrap_admin(&state, &email);

    let sid = rand_token(32);
    let _ = state
        .store
        .create_session(&sid, &id, state.config.session_ttl, "");
    let mut resp = Redirect::to(&safe_next(&f.next)).into_response();
    append_cookie(
        &mut resp,
        format!(
            "{SESSION_COOKIE}={sid}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax; Secure",
            state.config.session_ttl
        ),
    );
    append_cookie(
        &mut resp,
        format!("{CSRF_COOKIE}=; Path=/; Max-Age=0; HttpOnly"),
    );
    resp
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(sid) = cookie_value(&headers, SESSION_COOKIE) {
        let _ = state.store.delete_session(&sid);
    }
    let mut resp = page(
        "Signed out",
        "<p>You are signed out.</p><a href=\"/login\">Sign in again</a>",
    )
    .into_response();
    append_cookie(
        &mut resp,
        format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"),
    );
    resp
}

pub async fn logout_get(state: State<AppState>, headers: HeaderMap) -> Response {
    logout(state, headers).await
}

// ---------------------------------------------------------------------------
// GitHub upstream OAuth
// ---------------------------------------------------------------------------

pub async fn github_start(State(state): State<AppState>, Query(q): Query<NextQuery>) -> Response {
    let Some(client_id) = state.config.github_client_id.clone() else {
        return err_page("GitHub login is not configured");
    };
    let state_param = rand_token(24);
    let next = safe_next(&q.next.unwrap_or_default());

    let mut resp = Redirect::to(&format!(
        "https://github.com/login/oauth/authorize?client_id={client_id}&scope=read:user%20user:email&state={state_param}"
    ))
    .into_response();
    append_cookie(
        &mut resp,
        format!(
            "{GH_STATE_COOKIE}={state_param}; Path=/; Max-Age=600; HttpOnly; SameSite=Lax; Secure"
        ),
    );
    append_cookie(
        &mut resp,
        format!("{GH_NEXT_COOKIE}={next}; Path=/; Max-Age=600; HttpOnly; SameSite=Lax; Secure"),
    );
    resp
}

#[derive(Deserialize)]
pub struct GhCallback {
    #[serde(default)]
    code: String,
    #[serde(default)]
    state: String,
}

pub async fn github_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<GhCallback>,
) -> Response {
    let Some(expected) = cookie_value(&headers, GH_STATE_COOKIE).filter(|s| !s.is_empty()) else {
        return err_page("Missing GitHub state");
    };
    let next = cookie_value(&headers, GH_NEXT_COOKIE).unwrap_or_else(|| "/".into());

    if q.code.is_empty() || q.state.len() > 512 || !ct_eq(expected.as_bytes(), q.state.as_bytes()) {
        return err_page("GitHub callback failed validation");
    }
    let (Some(client_id), Some(client_secret)) = (
        state.config.github_client_id.clone(),
        state.config.github_client_secret.clone(),
    ) else {
        return err_page("GitHub login is not configured");
    };

    // Exchange code for a GitHub access token.
    let exchange = state
        .http
        .post("https://github.com/login/oauth/access_token")
        .header(header::ACCEPT, "application/json")
        .json(&json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "code": q.code,
        }))
        .send()
        .await;
    let Ok(exchange) = exchange else {
        return err_page("GitHub token exchange failed");
    };
    let Ok(body): Result<serde_json::Value, _> = exchange.json().await else {
        return err_page("GitHub token exchange returned invalid data");
    };
    let Some(gh_token) = body["access_token"].as_str().map(String::from) else {
        return err_page("GitHub did not return an access token");
    };

    // Fetch identity + primary email.
    let Ok(user_resp) = state
        .http
        .get("https://api.github.com/user")
        .bearer_auth(&gh_token)
        .header(header::USER_AGENT, "argus-idp")
        .send()
        .await
    else {
        return err_page("GitHub user fetch failed");
    };
    let Ok(gh_user): Result<serde_json::Value, _> = user_resp.json().await else {
        return err_page("GitHub user data invalid");
    };
    let Some(gh_id) = gh_user["id"].as_u64().map(|v| v.to_string()) else {
        return err_page("GitHub user id missing");
    };
    let login_name = gh_user["name"]
        .as_str()
        .or_else(|| gh_user["login"].as_str())
        .unwrap_or("GitHub User")
        .to_string();

    let mut primary_email = gh_user["email"].as_str().map(String::from);
    if primary_email.is_none() {
        if let Ok(emails) = state
            .http
            .get("https://api.github.com/user/emails")
            .bearer_auth(&gh_token)
            .header(header::USER_AGENT, "argus-idp")
            .send()
            .await
        {
            if let Ok(list) = emails.json::<serde_json::Value>().await {
                if let Some(arr) = list.as_array() {
                    primary_email = arr
                        .iter()
                        .find(|e| e["primary"].as_bool() == Some(true))
                        .and_then(|e| e["email"].as_str())
                        .map(String::from)
                        .or_else(|| {
                            arr.first()
                                .and_then(|e| e["email"].as_str())
                                .map(String::from)
                        });
                }
            }
        }
    }
    let Some(email) = primary_email.map(|e| e.to_lowercase()) else {
        return err_page("GitHub account has no accessible email");
    };

    // Find-or-create local user.
    let user = match state.store.user_by_github_id(&gh_id).ok().flatten() {
        Some(u) => u,
        None => match state.store.user_by_email(&email).ok().flatten() {
            Some(u) => {
                // Link GitHub to the existing local account via raw update.
                let _ = state.store.with_conn(|c| {
                    c.execute(
                        "UPDATE users SET github_id=?2 WHERE id=?1",
                        rusqlite::params![u.id, gh_id],
                    )?;
                    Ok(())
                });
                let _ = state
                    .store
                    .audit("github_link", Some(&u.id), json!({"gh_id": gh_id}));
                u
            }
            None => {
                let id = format!("usr_{}", rand_token(16));
                if state
                    .store
                    .create_user(&id, &email, &login_name, None, Some(&gh_id), false)
                    .is_err()
                {
                    return err_page("Could not provision account");
                }
                let _ = state.store.audit("register_github", Some(&id), json!({}));
                state
                    .store
                    .user_by_id(&id)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| crate::store::User {
                        id: id.clone(),
                        email: email.clone(),
                        name: login_name.clone(),
                        password_hash: None,
                        github_id: Some(gh_id.clone()),
                        is_admin: false,
                        disabled: false,
                    })
            }
        },
    };

    if user.disabled {
        return err_page("Account disabled");
    }
    promote_bootstrap_admin(&state, &user.email);
    let sid = rand_token(32);
    let _ = state
        .store
        .create_session(&sid, &user.id, state.config.session_ttl, "");
    let _ = state.store.audit("login_github", Some(&user.id), json!({}));

    let mut resp = Redirect::to(&safe_next(&next)).into_response();
    append_cookie(
        &mut resp,
        format!(
            "{SESSION_COOKIE}={sid}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax; Secure",
            state.config.session_ttl
        ),
    );
    append_cookie(&mut resp, format!("{GH_STATE_COOKIE}=; Path=/; Max-Age=0"));
    append_cookie(&mut resp, format!("{GH_NEXT_COOKIE}=; Path=/; Max-Age=0"));
    resp
}

// ---------------------------------------------------------------------------
// /authorize (OIDC authorization endpoint with consent)
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

fn authorize_error_redirect(
    redirect_uri: &str,
    error: &str,
    description: &str,
    oauth_state: &Option<String>,
) -> Response {
    let mut url = format!(
        "{redirect_uri}?error={error}&error_description={}",
        urlencoding::encode(description)
    );
    if let Some(st) = oauth_state {
        url.push_str(&format!("&state={}", urlencoding::encode(st)));
    }
    Redirect::to(&url).into_response()
}

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    // 1. Client + exact redirect_uri match.
    let Some(client) = state.store.client(&q.client_id).ok().flatten() else {
        return err_page("Unknown client_id");
    };
    if !client.redirect_uris.iter().any(|u| u == &q.redirect_uri) {
        return err_page("redirect_uri is not registered for this client");
    }
    if q.response_type != "code" {
        return authorize_error_redirect(
            &q.redirect_uri,
            "unsupported_response_type",
            "only code is supported",
            &q.state,
        );
    }
    let allowed_scopes = ["openid", "profile", "email", "offline_access"];
    if !q
        .scope
        .split(' ')
        .all(|s| allowed_scopes.contains(&s) || client.scopes.split(' ').any(|cs| cs == s))
    {
        return authorize_error_redirect(
            &q.redirect_uri,
            "invalid_scope",
            "scope not allowed",
            &q.state,
        );
    }
    if q.code_challenge.is_some() != (q.code_challenge_method.as_deref() == Some("S256")) {
        return authorize_error_redirect(
            &q.redirect_uri,
            "invalid_request",
            "PKCE S256 required when code_challenge present",
            &q.state,
        );
    }

    // 2. Session?
    let Some(user) = current_user(&state, &headers).await else {
        let full = build_authorize_url(&q);
        return Redirect::to(&format!("/login?next={}", urlencoding::encode(&full)))
            .into_response();
    };

    // 3. Persisted consent?
    match state
        .store
        .consent(&user.id, &q.client_id, &q.scope)
        .ok()
        .flatten()
        .as_deref()
    {
        Some("approved") => issue_code_and_redirect(&state, &user, &q).await,
        Some("denied") => {
            authorize_error_redirect(&q.redirect_uri, "access_denied", "user denied", &q.state)
        }
        _ => render_consent(&state, &headers, &user, &client, &q).await,
    }
}

fn build_authorize_url(q: &AuthorizeQuery) -> String {
    let mut params = vec![
        ("response_type", q.response_type.clone()),
        ("client_id", q.client_id.clone()),
        ("redirect_uri", q.redirect_uri.clone()),
        ("scope", q.scope.clone()),
    ];
    for (k, v) in [
        ("state", q.state.clone()),
        ("nonce", q.nonce.clone()),
        ("code_challenge", q.code_challenge.clone()),
        ("code_challenge_method", q.code_challenge_method.clone()),
    ] {
        if let Some(v) = v {
            params.push((k, v));
        }
    }
    let qs: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect();
    format!("/authorize?{}", qs.join("&"))
}

async fn render_consent(
    _state: &AppState,
    headers: &HeaderMap,
    user: &crate::store::User,
    client: &crate::store::Client,
    q: &AuthorizeQuery,
) -> Response {
    let csrf = ensure_csrf_cookie(headers);
    let hidden = build_authorize_url(q);
    let scopes = if q.scope.is_empty() {
        "openid".to_string()
    } else {
        q.scope.clone()
    };
    let body = format!(
        "<p><b>{}</b> requests access:</p>\
         <p style=\"font-family:monospace;font-size:.85rem\">{scopes}</p>\
         <p>Signed in as {}</p>\
         <form method=\"post\" action=\"/authorize\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
         <input type=\"hidden\" name=\"params\" value=\"{}\">\
         <button name=\"decision\" value=\"approve\">Approve</button>\
         <button name=\"decision\" value=\"deny\" style=\"background:#334155\">Deny</button></form>",
        client.name,
        html_escape(&user.email),
        urlencoding::encode(&hidden),
    );
    let mut resp = page("Consent", &body).into_response();
    append_cookie(
        &mut resp,
        format!("{CSRF_COOKIE}={csrf}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax; Secure"),
    );
    resp
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[derive(Deserialize)]
pub struct ConsentForm {
    pub decision: String,
    pub params: String,
    #[serde(default)]
    pub csrf: String,
}

pub async fn authorize_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<ConsentForm>,
) -> Response {
    if !csrf_ok(&headers, &f.csrf) {
        return err_page("Invalid CSRF token");
    }
    let Some(user) = current_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };

    // Re-parse the original authorize request from the hidden field.
    let raw = urlencoding::decode(&f.params)
        .unwrap_or_default()
        .to_string();
    let raw_qs = raw.rsplit_once('?').map(|(_, qs)| qs).unwrap_or(&raw);
    let Ok(q) = serde_urlencoded_decode(raw_qs) else {
        return err_page("Malformed consent payload");
    };

    let Some(client) = state.store.client(&q.client_id).ok().flatten() else {
        return err_page("Unknown client_id");
    };
    if !client.redirect_uris.iter().any(|u| u == &q.redirect_uri) {
        return err_page("redirect_uri mismatch");
    }

    let approved = f.decision == "approve";
    let scope = if q.scope.is_empty() {
        "openid".into()
    } else {
        q.scope.clone()
    };
    let _ = state.store.save_consent(
        &user.id,
        &q.client_id,
        &scope,
        if approved { "approved" } else { "denied" },
    );
    let _ = state.store.audit(
        if approved {
            "consent_approved"
        } else {
            "consent_denied"
        },
        Some(&user.id),
        json!({"client": q.client_id, "scope": scope}),
    );

    if approved {
        issue_code_and_redirect(&state, &user, &q).await
    } else {
        authorize_error_redirect(&q.redirect_uri, "access_denied", "user denied", &q.state)
    }
}

fn serde_urlencoded_decode(qs: &str) -> anyhow::Result<AuthorizeQuery> {
    let mut map = std::collections::HashMap::new();
    for pair in qs.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), urlencoding::decode(v)?.to_string());
        }
    }
    Ok(AuthorizeQuery {
        response_type: map.get("response_type").cloned().unwrap_or_default(),
        client_id: map.get("client_id").cloned().unwrap_or_default(),
        redirect_uri: map.get("redirect_uri").cloned().unwrap_or_default(),
        scope: map.get("scope").cloned().unwrap_or_default(),
        state: map.get("state").cloned(),
        nonce: map.get("nonce").cloned(),
        code_challenge: map.get("code_challenge").cloned(),
        code_challenge_method: map.get("code_challenge_method").cloned(),
    })
}

async fn issue_code_and_redirect(
    state: &AppState,
    user: &crate::store::User,
    q: &AuthorizeQuery,
) -> Response {
    let code = rand_token(32);
    let ac = crate::store::AuthCode {
        code: code.clone(),
        client_id: q.client_id.clone(),
        redirect_uri: q.redirect_uri.clone(),
        scope: if q.scope.is_empty() {
            "openid".into()
        } else {
            q.scope.clone()
        },
        user_id: user.id.clone(),
        code_challenge: q.code_challenge.clone(),
        code_challenge_meth: q.code_challenge_method.clone(),
        nonce: q.nonce.clone(),
        issued_at: now(),
        expires_at: now() + 300, // 5-minute codes per RFC 6749
    };
    if state.store.put_auth_code(&ac).is_err() {
        return err_page("Could not store authorization code");
    }
    let _ = state.store.audit(
        "auth_code_issued",
        Some(&user.id),
        json!({"client": q.client_id}),
    );
    let mut url = format!(
        "{}?code={}{}",
        q.redirect_uri,
        urlencoding::encode(&code),
        q.state
            .as_ref()
            .map(|s| format!("&state={}", urlencoding::encode(s)))
            .unwrap_or_default(),
    );
    // Preserve any existing query on the redirect_uri.
    if q.redirect_uri.contains('?') {
        url = format!(
            "{}&code={}{}",
            q.redirect_uri,
            urlencoding::encode(&code),
            q.state
                .as_ref()
                .map(|s| format!("&state={}", urlencoding::encode(s)))
                .unwrap_or_default(),
        );
    }
    Redirect::to(&url).into_response()
}

// ---------------------------------------------------------------------------
// Agent identities (phase 2): client_credentials + management API
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AgentCreate {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Register an agent identity. Session-authenticated; the calling human is
/// the owner. Returns the plaintext secret exactly once.
pub async fn agents_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AgentCreate>,
) -> Response {
    let Some(user) = current_user(&state, &headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "login required"})),
        )
            .into_response();
    };
    let name = body.name.trim();
    if name.is_empty()
        || name.len() > 120
        || state
            .store
            .agents_for_owner(&user.id)
            .map(|v| v.len())
            .unwrap_or(99)
            >= 100
    {
        return err_page("Invalid agent name or quota exceeded");
    }
    let allowed = [
        "miser:route",
        "hive:delegate",
        "relay:call",
        "sentiel:ingest",
        "aegis:egress",
        "patroclus:authz",
    ];
    let scopes: Vec<String> = body
        .scopes
        .iter()
        .filter(|s| allowed.contains(&s.as_str()))
        .cloned()
        .collect();

    let secret = format!("agt_{}", rand_token(32));
    let hash = match crate::crypto::hash_password(&secret) {
        Ok(h) => h,
        Err(_) => return err_page("Internal error"),
    };
    let id = format!("agt_{}", rand_token(12));
    if state
        .store
        .create_agent(&id, &user.id, name, &hash, &scopes, &body.metadata)
        .is_err()
    {
        return err_page("Could not create agent");
    }
    let _ = state.store.audit(
        "agent_created",
        Some(&user.id),
        json!({"agent": id, "name": name}),
    );
    (
        StatusCode::CREATED,
        axum::Json(json!({
            "agent_id": id,
            "secret": secret,
            "note": "Store this secret now — it is not retrievable later.",
        })),
    )
        .into_response()
}

pub async fn agents_list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user) = current_user(&state, &headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "login required"})),
        )
            .into_response();
    };
    let agents = state.store.agents_for_owner(&user.id).unwrap_or_default();
    axum::Json(json!({ "agents": agents.iter().map(|a| json!({
        "id": a.id, "name": a.name, "scopes": a.scopes, "status": a.status,
    })).collect::<Vec<_>>() }))
    .into_response()
}

#[derive(Deserialize)]
pub struct AgentStatusUpdate {
    pub status: String,
}

/// Kill switch / re-activate — ownership enforced in the UPDATE itself.
pub async fn agents_set_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(agent_id): axum::extract::Path<String>,
    Json(body): Json<AgentStatusUpdate>,
) -> Response {
    let Some(user) = current_user(&state, &headers).await else {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "login required"})),
        )
            .into_response();
    };
    if !["active", "revoked"].contains(&body.status.as_str()) {
        return err_page("status must be active|revoked");
    }
    match state
        .store
        .set_agent_status(&agent_id, &user.id, &body.status)
    {
        Ok(true) => {
            let _ = state.store.audit(
                if body.status == "revoked" {
                    "agent_revoked"
                } else {
                    "agent_reactivated"
                },
                Some(&user.id),
                json!({"agent": agent_id}),
            );
            axum::Json(json!({"agent_id": agent_id, "status": body.status})).into_response()
        }
        _ => (
            StatusCode::NOT_FOUND,
            axum::Json(json!({"error": "not found"})),
        )
            .into_response(),
    }
}

/// Authenticate an agent's Basic credentials → Option<Agent> (active only).
async fn authenticate_agent(state: &AppState, headers: &HeaderMap) -> Option<crate::store::Agent> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = auth.strip_prefix("Basic ")?;
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    if !id.starts_with("agt_") {
        return None;
    }
    let agent = state.store.agent_by_id(id).ok().flatten()?;
    if agent.status != "active" {
        return None;
    }
    if !crate::crypto::verify_password(secret, &agent.secret_hash) {
        return None;
    }
    Some(agent)
}

// ---------------------------------------------------------------------------
// /token — authorization_code + refresh_token + client_credentials
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub code_verifier: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub scope: String,
}

fn token_error(code: &str, desc: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(json!({"error": code, "error_description": desc})),
    )
        .into_response()
}

pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<TokenRequest>,
) -> Response {
    // Basic auth may carry client credentials or agent credentials.
    let mut basic_client: Option<(String, String)> = None;
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(enc) = auth.strip_prefix("Basic ") {
            use base64::Engine;
            if let Ok(dec) = base64::engine::general_purpose::STANDARD.decode(enc) {
                if let Ok(s) = String::from_utf8(dec) {
                    if let Some((id, sec)) = s.split_once(':') {
                        basic_client = Some((id.to_string(), sec.to_string()));
                    }
                }
            }
        }
    }

    match f.grant_type.as_str() {
        // ---- machine identity flow ----
        "client_credentials" => {
            let creds = basic_client
                .clone()
                .unwrap_or((f.client_id.clone(), f.client_secret.clone()));
            if !creds.0.starts_with("agt_") {
                return token_error("invalid_client", "agent credentials required");
            }
            let Some(agent) = authenticate_agent(&state, &headers).await else {
                return token_error("invalid_client", "invalid agent credentials");
            };
            let scope = if f.scope.is_empty() {
                agent.scopes.join(" ")
            } else {
                f.scope.clone()
            };
            if scope
                .split(' ')
                .any(|s| !agent.scopes.contains(&s.to_string()))
            {
                return token_error("invalid_scope", "scope exceeds agent grant");
            }
            let owner = state.store.user_by_id(&agent.owner_user_id).ok().flatten();
            let subject_user = owner.unwrap_or(crate::store::User {
                id: format!("owner-of-{}", agent.id),
                email: String::new(),
                name: String::new(),
                password_hash: None,
                github_id: None,
                is_admin: false,
                disabled: false,
            });
            let (access, _exp) = match tokens::mint_access_token(
                &state.key,
                state.config.external_url.trim_end_matches('/'),
                &subject_user,
                &agent.id,
                &scope,
                state.config.access_token_ttl.min(900),
            ) {
                Ok(t) => t,
                Err(_) => return token_error("server_error", "signing failed"),
            };
            let _ = state.store.touch_agent(&agent.id);
            let _ = state.store.audit(
                "agent_token",
                Some(&subject_user.id),
                json!({"agent": agent.id}),
            );
            (
                [(header::CACHE_CONTROL, "no-store")],
                Json(json!({
                    "access_token": access,
                    "token_type": "Bearer",
                    "expires_in": 900,
                    "scope": scope,
                    "agent_id": agent.id,
                })),
            )
                .into_response()
        }

        // ---- interactive flows ----
        "authorization_code" => {
            let client_id = basic_client
                .as_ref()
                .map(|c| c.0.clone())
                .unwrap_or(f.client_id.clone());
            let secret = basic_client
                .as_ref()
                .map(|c| c.1.clone())
                .unwrap_or_else(|| f.client_secret.clone());

            let Some(ac) = state.store.take_auth_code(&f.code).ok().flatten() else {
                return token_error("invalid_grant", "code invalid, expired, or replayed");
            };
            if ac.client_id != client_id || ac.redirect_uri != f.redirect_uri {
                return token_error(
                    "invalid_grant",
                    "code was issued to a different client/redirect",
                );
            }

            let client = state.store.client(&client_id).ok().flatten();
            let is_confidential = client
                .as_ref()
                .map(|c| c.secret_hash.is_some())
                .unwrap_or(false);
            if is_confidential {
                let Some(hash) = client.as_ref().and_then(|c| c.secret_hash.clone()) else {
                    return token_error("invalid_client", "client misconfigured");
                };
                if !crate::crypto::verify_password(&secret, &hash) {
                    return token_error("invalid_client", "bad client secret");
                }
            }

            // PKCE verification for public clients.
            if let Some(challenge) = ac.code_challenge.clone() {
                if crate::crypto::s256_challenge(&f.code_verifier) != challenge {
                    return token_error("invalid_grant", "PKCE verification failed");
                }
            }

            let Some(user) = state.store.user_by_id(&ac.user_id).ok().flatten() else {
                return token_error("invalid_grant", "user gone");
            };
            if user.disabled {
                return token_error("invalid_grant", "user disabled");
            }

            finish_interactive_token(
                &state,
                &user,
                &ac.client_id,
                &ac.scope,
                ac.nonce.as_deref(),
                f.refresh_token.is_empty(),
            )
            .await
        }

        "refresh_token" => {
            let replacement = rand_token(32);
            let Some((user_id, client_id, scope)) = state
                .store
                .rotate_refresh(&f.refresh_token, &replacement)
                .ok()
                .flatten()
            else {
                return token_error("invalid_grant", "refresh token invalid or reused");
            };
            let Some(user) = state.store.user_by_id(&user_id).ok().flatten() else {
                return token_error("invalid_grant", "user gone");
            };
            let access = tokens::mint_access_token(
                &state.key,
                state.config.external_url.trim_end_matches('/'),
                &user,
                &client_id,
                &scope,
                state.config.access_token_ttl,
            );
            let Ok((access, _)) = access else {
                return token_error("server_error", "signing failed");
            };
            (
                [(header::CACHE_CONTROL, "no-store")],
                Json(json!({
                    "access_token": access,
                    "token_type": "Bearer",
                    "expires_in": state.config.access_token_ttl,
                    "refresh_token": replacement,
                    "scope": scope,
                })),
            )
                .into_response()
        }

        _ => token_error(
            "unsupported_grant_type",
            "supported: authorization_code, refresh_token, client_credentials",
        ),
    }
}

async fn finish_interactive_token(
    state: &AppState,
    user: &crate::store::User,
    client_id: &str,
    scope: &str,
    nonce: Option<&str>,
    want_refresh: bool,
) -> Response {
    let issuer = state.config.external_url.trim_end_matches('/');
    let Ok((access, exp)) = tokens::mint_access_token(
        &state.key,
        issuer,
        user,
        client_id,
        scope,
        state.config.access_token_ttl,
    ) else {
        return token_error("server_error", "signing failed");
    };

    let id_token = if scope.split(' ').any(|s| s == "openid") {
        tokens::mint_id_token(
            &state.key,
            issuer,
            user,
            client_id,
            nonce,
            state.config.access_token_ttl,
        )
        .ok()
    } else {
        None
    };

    // Refresh only when offline_access was consented.
    let refresh = if want_refresh && scope.split(' ').any(|s| s == "offline_access") {
        let rt = rand_token(32);
        let _ = state
            .store
            .put_refresh(&rt, &user.id, client_id, scope, 30 * 24 * 3600);
        Some(rt)
    } else {
        None
    };

    let mut body = json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": state.config.access_token_ttl,
        "exp": exp,
        "scope": scope,
    });
    if let Some(idt) = id_token {
        body["id_token"] = json!(idt);
    }
    if let Some(rt) = refresh {
        body["refresh_token"] = json!(rt);
    }
    ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// /userinfo + /introspect
// ---------------------------------------------------------------------------

pub async fn userinfo(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let claims = match bearer_claims(&state, &headers).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let sub = claims.sub.clone();
    let is_agent = claims.aud.starts_with("agt_");
    axum::Json(if is_agent {
        let agent = state.store.agent_by_id(&claims.aud).ok().flatten();
        json!({
            "sub": sub,
            "kind": "agent",
            "agent_id": claims.aud,
            "acting_for": claims.email.clone().unwrap_or_default(),
            "name": agent.map(|a| a.name).unwrap_or_default(),
        })
    } else {
        match state.store.user_by_id(&sub).ok().flatten() {
            Some(u) => json!({"sub": u.id, "kind": "human", "email": u.email, "name": u.name}),
            None => json!({"sub": sub}),
        }
    })
    .into_response()
}

async fn bearer_claims(state: &AppState, headers: &HeaderMap) -> Result<tokens::Claims, Response> {
    let tok = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    tokens::verify(
        &state.key,
        state.config.external_url.trim_end_matches('/'),
        tok,
    )
    .map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "invalid_token"})),
        )
            .into_response()
    })
}

#[derive(Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
}

/// RFC 7662. Resource servers (hub, products) call this to honor the agent
/// kill switch instantly: revoked agents fail here even with unexpired JWTs.
pub async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<IntrospectRequest>,
) -> Response {
    // Caller must be a registered confidential client.
    let mut caller_ok = false;
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(enc) = auth.strip_prefix("Basic ") {
            use base64::Engine;
            if let Ok(dec) = base64::engine::general_purpose::STANDARD.decode(enc) {
                if let Ok(s) = String::from_utf8(dec) {
                    if let Some((cid, sec)) = s.split_once(':') {
                        if cid.starts_with("svc_") {
                            if let Some(Some(hash)) = state
                                .store
                                .client(cid)
                                .ok()
                                .flatten()
                                .map(|c| c.secret_hash)
                            {
                                caller_ok = crate::crypto::verify_password(sec, &hash);
                            }
                        }
                    }
                }
            }
        }
    }
    if !caller_ok {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }

    let inactive = || (axum::Json(json!({"active": false}))).into_response();
    let Ok(claims) = tokens::verify(
        &state.key,
        state.config.external_url.trim_end_matches('/'),
        &f.token,
    ) else {
        return inactive();
    };
    // Agent tokens die instantly when the agent row is revoked.
    if claims.aud.starts_with("agt_") {
        match state.store.agent_by_id(&claims.aud).ok().flatten() {
            Some(a) if a.status == "active" => {}
            _ => return inactive(),
        }
    } else {
        match state.store.user_by_id(&claims.sub).ok().flatten() {
            Some(u) if !u.disabled => {}
            _ => return inactive(),
        }
    }
    axum::Json(json!({
        "active": true,
        "sub": claims.sub,
        "aud": claims.aud,
        "iss": claims.iss,
        "exp": claims.exp,
        "scope": "",
    }))
    .into_response()
}
