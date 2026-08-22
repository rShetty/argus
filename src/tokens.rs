//! ID/access token minting (RS256) and claims.

use crate::crypto::SigningKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: u64,
    pub iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

pub fn mint_access_token(
    key: &SigningKey,
    issuer: &str,
    user: &crate::store::User,
    client_id: &str,
    scope: &str,
    ttl_secs: u64,
) -> anyhow::Result<(String, u64)> {
    let now = now_epoch();
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": user.id,
        "aud": client_id,
        "exp": now + ttl_secs,
        "iat": now,
        "scope": scope,
        "email": user.email,
        "name": user.name,
    });
    let header = json_header(&key.kid);
    let signing_input = format!("{}.{}", b64url_json(&header)?, b64url_json(&claims)?);
    let sig = key.sign_rs256(signing_input.as_bytes())?;
    Ok((
        format!("{signing_input}.{}", crate::crypto::b64url(&sig)),
        now + ttl_secs,
    ))
}

pub fn mint_id_token(
    key: &SigningKey,
    issuer: &str,
    user: &crate::store::User,
    client_id: &str,
    nonce: Option<&str>,
    ttl_secs: u64,
) -> anyhow::Result<String> {
    let now = now_epoch();
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": user.id,
        "aud": client_id,
        "exp": now + ttl_secs,
        "iat": now,
        "nonce": nonce,
        "email": user.email,
        "name": user.name,
    });
    let header = json_header(&key.kid);
    let signing_input = format!("{}.{}", b64url_json(&header)?, b64url_json(&claims)?);
    let sig = key.sign_rs256(signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", crate::crypto::b64url(&sig)))
}

/// Verify an Argus-issued access token (used by resource servers / hub).
pub fn verify(key: &SigningKey, issuer: &str, token: &str) -> anyhow::Result<Claims> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) => (h, p, s),
        _ => anyhow::bail!("malformed token"),
    };
    if parts.next().is_some() {
        anyhow::bail!("malformed token");
    }
    let signing_input = format!("{h}.{p}");
    let sig = engine.decode(s)?;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use sha2::Sha256;
    let vk: VerifyingKey<Sha256> = VerifyingKey::new(key.public.clone());
    vk.verify(
        signing_input.as_bytes(),
        &Signature::try_from(sig.as_slice())?,
    )?;
    let claims: Claims = serde_json::from_slice(&engine.decode(p)?)?;
    if claims.iss != issuer {
        anyhow::bail!("bad issuer");
    }
    if claims.exp < now_epoch() {
        anyhow::bail!("token expired");
    }
    Ok(claims)
}

fn json_header(kid: &str) -> serde_json::Value {
    serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": kid})
}

fn b64url_json(v: &serde_json::Value) -> anyhow::Result<String> {
    Ok(crate::crypto::b64url(serde_json::to_string(v)?.as_bytes()))
}

pub fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
