//! End-to-end smoke tests: discovery, register/login (CSRF), authorize with
//! PKCE + consent, token exchange, userinfo, agent client_credentials +
//! introspection kill switch.

use argus::{router, AppState, Config};
use http_body_util::BodyExt;
use std::collections::HashMap;
use tower::ServiceExt;

fn test_state() -> AppState {
    let mut services = HashMap::new();
    services.insert("demo".to_string(), crate_client_entry());
    let dir = std::env::temp_dir().join(format!("argus-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let cfg = Config {
        listen: "127.0.0.1:0".into(),
        database: dir.join("test.db").display().to_string(),
        external_url: "http://127.0.0.1:8443".into(),
        signing_key_pem_path: Some(dir.join("test-key.pem").display().to_string()),
        access_token_ttl: 600,
        session_ttl: 3600,
        github_client_id: None,
        github_client_secret: None,
        bootstrap_admin_email: Some("admin@test.dev".into()),
    };
    AppState {
        config: std::sync::Arc::new(cfg),
        store: std::sync::Arc::new(
            argus::store::Store::open(&dir.join("test.db").display().to_string()).unwrap(),
        ),
        key: std::sync::Arc::new(
            argus::crypto::SigningKey::load_or_create(Some(
                &dir.join("test-key.pem").display().to_string(),
            ))
            .unwrap(),
        ),
        http: reqwest::Client::new(),
    }
}

fn crate_client_entry() -> serde_json::Value {
    serde_json::json!({})
}

async fn req(
    app: axum::Router,
    method: &str,
    uri: &str,
    headers: Vec<(&str, String)>,
    body: Option<String>,
) -> (u16, String, Vec<String>) {
    let mut b = axum::http::Request::builder().method(method).uri(uri);
    for (k, v) in &headers {
        b = b.header(*k, v);
    }
    let r = b
        .body(axum::body::Body::from(body.unwrap_or_default()))
        .unwrap();
    let resp = app.oneshot(r).await.unwrap();
    let status = resp.status().as_u16();
    let set_cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        String::from_utf8_lossy(&bytes).to_string(),
        set_cookies,
    )
}

#[tokio::test]
async fn discovery_and_jwks_work() {
    let app = router(test_state());
    let (s, b, _) = req(
        app.clone(),
        "GET",
        "/.well-known/openid-configuration",
        vec![],
        None,
    )
    .await;
    assert_eq!(s, 200);
    assert!(b.contains("\"issuer\"") && b.contains("\"registration_endpoint\""));
    let (s2, b2, _) = req(app, "GET", "/jwks.json", vec![], None).await;
    assert_eq!(s2, 200);
    assert!(b2.contains("RS256") && b2.contains("\"n\""));
}

#[tokio::test]
async fn full_oidc_flow_with_pkce_and_consent() {
    let state = test_state();
    // Register a public OIDC client directly.
    state.store.with_conn(|c| {
        c.execute(
            "INSERT INTO clients (client_id, secret_hash, name, redirect_uris, scopes, created_at) VALUES (?1,NULL,'Demo','http://127.0.0.1:9001/cb','openid profile email offline_access',?2)",
            rusqlite::params!["svc_demo", 0],
        )
        .unwrap();
        Ok(())
    }).unwrap();

    let app = router(state.clone());

    // ---- register a user ----
    let (s, _, cookies) = req(app.clone(), "GET", "/register", vec![], None).await;
    assert_eq!(s, 200);
    let csrf = extract_cookie(&cookies, "argus_csrf");
    let form =
        format!("csrf={csrf}&name=Test&email=test%40test.dev&password=supersecret123&next=%2F");
    let (s, _, cookies) = req(
        app.clone(),
        "POST",
        "/register",
        vec![
            ("content-type", "application/x-www-form-urlencoded".into()),
            ("cookie", format!("argus_csrf={csrf}")),
        ],
        Some(form),
    )
    .await;
    assert_eq!(s, 303, "register should redirect after success");
    let session = extract_cookie(&cookies, "argus_session");
    assert!(!session.is_empty(), "session cookie must be set");

    // ---- authorize (PKCE) → consent screen ----
    let verifier = "correct-horse-battery-staple-01";
    let challenge = argus::crypto::s256_challenge(verifier);
    let authz_url = format!(
        "/authorize?response_type=code&client_id=svc_demo&redirect_uri=http%3A%2F%2F127.0.0.1%3A9001%2Fcb&scope=openid%20offline_access&state=xyz&nonce=n-1&code_challenge={challenge}&code_challenge_method=S256"
    );
    let (s, _, _) = req(
        app.clone(),
        "GET",
        &authz_url,
        vec![("cookie", format!("argus_session={session}"))],
        None,
    )
    .await;
    assert_eq!(s, 200, "consent screen expected (session={session})");

    // ---- approve consent ----
    // Pull fresh csrf from consent response by re-requesting.
    let (_, body, cookies) = req(
        app.clone(),
        "GET",
        &authz_url,
        vec![("cookie", format!("argus_session={session}"))],
        None,
    )
    .await;
    let csrf = extract_cookie(&cookies, "argus_csrf");
    assert!(body.contains("Consent"), "{body}");
    // params hidden field is urlencoded /authorize?...
    let params_enc = body
        .split("name=\"params\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap()
        .to_string();
    let form = format!("csrf={csrf}&decision=approve&params={params_enc}");
    let (s, body, _) = req(
        app.clone(),
        "POST",
        "/authorize",
        vec![
            ("content-type", "application/x-www-form-urlencoded".into()),
            (
                "cookie",
                format!("argus_session={session}; argus_csrf={csrf}"),
            ),
        ],
        Some(form.clone()),
    )
    .await;
    assert_eq!(s, 303, "consent approval should redirect: {body}");
    let location = body; // NOTE: RedirectResponse location not in body; use headers below

    // Extract code from redirect Location header via raw request instead:
    let bld = axum::http::Request::builder()
        .method("POST")
        .uri("/authorize")
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            "cookie",
            format!("argus_session={session}; argus_csrf={csrf}"),
        );
    let r = bld.body(axum::body::Body::from(form)).unwrap();
    let resp = router(state.clone()).oneshot(r).await.unwrap();
    assert_eq!(resp.status(), 303);
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        loc.contains("code="),
        "location={loc}, first attempt gave {location}"
    );
    let code = loc
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();

    // ---- token exchange (PKCE, public client) ----
    let tok_form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=http%3A%2F%2F127.0.0.1%3A9001%2Fcb&client_id=svc_demo&code_verifier={verifier}"
    );
    let (s, body, _) = req(
        app.clone(),
        "POST",
        "/token",
        vec![("content-type", "application/x-www-form-urlencoded".into())],
        Some(tok_form),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    let tok: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(tok["access_token"].is_string());
    assert!(
        tok["id_token"].is_string(),
        "openid scope must yield id_token: {tok}"
    );
    assert!(
        tok["refresh_token"].is_string(),
        "offline_access must yield refresh_token"
    );

    // ---- userinfo ----
    let (s, body, _) = req(
        app.clone(),
        "GET",
        "/userinfo",
        vec![(
            "authorization",
            format!("Bearer {}", tok["access_token"].as_str().unwrap()),
        )],
        None,
    )
    .await;
    assert_eq!(s, 200);
    assert!(body.contains("\"kind\":\"human\""), "{body}");
}

#[tokio::test]
async fn dynamic_client_registration_creates_public_client() {
    let state = test_state();
    let app = router(state.clone());

    let (status, body, _) = req(
        app,
        "POST",
        "/register-client",
        vec![("content-type", "application/json".into())],
        Some(r#"{"client_name":"CIMD Client","redirect_uris":["http://127.0.0.1:9001/cb"],"scope":"openid profile email offline_access","token_endpoint_auth_method":"none"}"#.into()),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let registered: serde_json::Value = serde_json::from_str(&body).unwrap();
    let client_id = registered["client_id"].as_str().unwrap();
    assert!(client_id.starts_with("dcr_"));
    assert_eq!(registered["token_endpoint_auth_method"], "none");

    let client = state.store.client(client_id).unwrap().unwrap();
    assert!(client.secret_hash.is_none());
    assert_eq!(client.registration_type, "dynamic");
}

fn extract_cookie(cookies: &[String], name: &str) -> String {
    cookies
        .iter()
        .find_map(|c| {
            let kv = c.split(';').next()?;
            let (k, v) = kv.split_once('=')?;
            (k == name).then(|| v.to_string())
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn agent_lifecycle_credentials_and_kill_switch() {
    let state = test_state();
    let app = router(state.clone());

    // Create an owner user directly + session.
    state
        .store
        .create_user(
            "usr_owner",
            "owner@test.dev",
            "Owner",
            Some(&argus::crypto::hash_password("pw1234567890").unwrap()),
            None,
            false,
        )
        .unwrap();
    state
        .store
        .create_session("sess-owner", "usr_owner", 3600, "")
        .unwrap();

    // Register an agent.
    let (s, body, _) = req(
        app.clone(),
        "POST",
        "/api/agents",
        vec![
            ("cookie", "argus_session=sess-owner".into()),
            ("content-type", "application/json".into()),
        ],
        Some(r#"{"name":"ci-bot","scopes":["miser:route"]}"#.into()),
    )
    .await;
    assert_eq!(s, 201, "{body}");
    let created: serde_json::Value = serde_json::from_str(&body).unwrap();
    let agent_id = created["agent_id"].as_str().unwrap().to_string();
    let secret = created["secret"].as_str().unwrap().to_string();

    // client_credentials grant works.
    use base64::Engine;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{agent_id}:{secret}"));
    let (s, body, _) = req(
        app.clone(),
        "POST",
        "/token",
        vec![
            ("content-type", "application/x-www-form-urlencoded".into()),
            ("authorization", format!("Basic {basic}")),
        ],
        Some("grant_type=client_credentials".into()),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    let tok: serde_json::Value = serde_json::from_str(&body).unwrap();
    let access = tok["access_token"].as_str().unwrap().to_string();

    // Introspection says active (using confidential caller).
    state.store.with_conn(|c| {
        c.execute(
            "INSERT INTO clients (client_id, secret_hash, name, redirect_uris, scopes, created_at) VALUES (?1, ?2, 'Hub','http://x/cb','',?3)",
            rusqlite::params!["svc_hub", argus::crypto::hash_password("hub-secret").unwrap(), 0],
        ).unwrap();
        Ok(())
    }).unwrap();
    let hub_basic = base64::engine::general_purpose::STANDARD.encode("svc_hub:hub-secret");
    let (s, body, _) = req(
        app.clone(),
        "POST",
        "/introspect",
        vec![
            ("content-type", "application/x-www-form-urlencoded".into()),
            ("authorization", format!("Basic {hub_basic}")),
        ],
        Some(format!("token={access}")),
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["active"],
        true
    );

    // Kill switch.
    let (s, body, _) = req(
        app.clone(),
        "POST",
        &format!("/api/agents/{agent_id}/status"),
        vec![
            ("cookie", "argus_session=sess-owner".into()),
            ("content-type", "application/json".into()),
        ],
        Some(r#"{"status":"revoked"}"#.into()),
    )
    .await;
    assert_eq!(s, 200, "{body}");

    // Same token now introspects as inactive.
    let (s, body, _) = req(
        app,
        "POST",
        "/introspect",
        vec![
            ("content-type", "application/x-www-form-urlencoded".into()),
            ("authorization", format!("Basic {hub_basic}")),
        ],
        Some(format!("token={access}")),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["active"],
        false,
        "revoked agent token must be inactive immediately"
    );
}
