# Argus 👁

**OIDC identity provider for the six-project governance ecosystem.**
The hundred-eyed guardian: one never-sleeping watchman over every gateway.

Humans sign in once (password or GitHub) and every ecosystem product trusts
the same identity. Agents (Hive agents, CI jobs, MCP connectors) get their
own machine identities — owned by a human, scope-bounded, and revocable
instantly via the kill switch.

## Roles

| Principal | Flow | Proof |
|---|---|---|
| Human | OIDC authorization_code + PKCE | RS256 `id_token` / `access_token` |
| Agent | OAuth2 `client_credentials` (Basic auth, `agt_…` secret) | RS256 token bound to owner + scopes |

## Endpoints

```
GET  /.well-known/openid-configuration   discovery
GET  /jwks.json                          public signing keys
GET/POST /login, /register               interactive sessions
GET  /auth/github[/callback]             GitHub upstream login
GET/POST /authorize                      authorization + consent
POST /token                              authorization_code | refresh_token | client_credentials
GET  /userinfo                           human or agent profile from bearer token
POST /introspect                         RFC 7662 — honors agent kill switch instantly
GET  /health
POST /api/agents                         register an agent (session required)
GET  /api/agents                         list own agents
POST /api/agents/{id}/status             revoke / re-activate (kill switch)
```

## Run

```bash
cargo run --release -- argus.toml
# → http://127.0.0.1:8443
```

## Tests

```bash
cargo test   # e2e: register→login→authorize(PKCE)→consent→token→userinfo,
             #      agent lifecycle incl. kill-switch introspection flip
```

## Security notes

- Passwords + agent secrets: **Argon2id**, constant-time compares everywhere.
- PKCE S256 enforced whenever a challenge is present; exact-match redirect URIs.
- CSRF double-submit on all forms; session cookies HttpOnly/SameSite=Lax.
- Agent tokens carry ≤15-min TTLs; `/introspect` refuses revoked agents even
  with unexpired JWTs — resource servers get instant revocation without key rotation.
- Security headers on every response (nosniff, DENY, HSTS).

## Deploy

See `deploy/` — hardened systemd unit + nginx vhost template (TLS at
`id.rajeev.me`). Put secrets in `/etc/argus/env`
(`GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`).
