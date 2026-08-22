//! Crypto: Argon2id password hashing + RS256 signing keys / JWKS.

use anyhow::Context;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use base64::Engine;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?
        .to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// A single active signing key. v1: one key; rotation lands with JWKS history.
pub struct SigningKey {
    pub kid: String,
    private: RsaPrivateKey,
    pub public: RsaPublicKey,
}

impl SigningKey {
    /// Load PEM from disk or generate-and-persist a fresh key (first boot).
    pub fn load_or_create(path: Option<&str>) -> anyhow::Result<Self> {
        let (pem, created): (String, bool) = match path {
            Some(p) => match std::fs::read_to_string(p) {
                Ok(s) => (s, false),
                Err(_) if std::fs::metadata(p).is_err() => {
                    let pem = generate_pem()?;
                    std::fs::write(p, &pem).context("persist new signing key")?;
                    (pem, true)
                }
                Err(e) => return Err(e.into()),
            },
            None => (generate_pem()?, true),
        };
        if created {
            tracing::info!("generated new RS256 signing key");
        }
        let key = RsaPrivateKey::from_pkcs8_pem(pem.trim()).context("parse signing key PEM")?;
        Ok(Self::from_key(key))
    }

    fn from_key(private: RsaPrivateKey) -> Self {
        let public = RsaPublicKey::from(&private);
        // kid = SHA-256 of the SPKI public key, first 16 hex chars.
        let mut spki = Vec::new();
        public
            .to_public_key_der()
            .expect("encode public key")
            .as_bytes()
            .iter()
            .for_each(|b| spki.push(*b));
        let digest = Sha256::digest(&spki);
        let kid: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
        Self {
            kid,
            private,
            public,
        }
    }

    pub fn sign_rs256(&self, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Sha256;
        let sk: SigningKey<Sha256> = SigningKey::new(self.private.clone());
        Ok(sk.sign(payload).to_vec())
    }

    pub fn jwk(&self) -> serde_json::Value {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let e = self.public.e().to_bytes_be();
        let n = self.public.n().to_bytes_be();
        serde_json::json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": URL_SAFE_NO_PAD.encode(n),
            "e": URL_SAFE_NO_PAD.encode(e),
        })
    }
}

fn generate_pem() -> anyhow::Result<String> {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048)?;
    key.to_pkcs8_pem(LineEnding::LF)
        .map(|doc| doc.as_str().to_owned())
        .context("encode pkcs8")
}

/// b64url no-pad helper used by the token endpoint (PKCE S256 etc).
pub fn b64url(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    URL_SAFE_NO_PAD.encode(data)
}

pub fn s256_challenge(verifier: &str) -> String {
    b64url(&Sha256::digest(verifier.as_bytes()))
}
