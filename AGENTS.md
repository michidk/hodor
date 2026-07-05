# Agents

## Project Overview

Hodor is a tiny Rust reverse proxy that gates any web app behind a single shared password, with optional TOTP two-factor authentication and optional passkey (WebAuthn) login. It runs as a Docker sidecar — no users, no database, no OAuth. One binary, one password, one login page.

## Architecture

Single-binary HTTP server built on axum + hyper. Everything lives in `src/main.rs`, with the default templates in `src/template.html` (login page), `src/error_template.html` (error page), and `src/passkeys_template.html` (passkey management page).

### Request Flow

1. Request arrives at hodor
2. `/_gate/health` → bypass auth, return 200
3. `/_gate/login` (POST) → rate-limit check → constant-time password compare (+ TOTP code check when `TOTP_SECRET` is set) → set session cookie
4. `/_gate/logout` → clear cookie, redirect
5. `/_gate/passkeys` (GET) → passkey management page (requires session; only when passkeys enabled)
6. `/_gate/passkey/register/{start,finish}` (POST) → WebAuthn registration ceremony (requires session)
7. `/_gate/passkey/login/{start,finish}` (POST) → WebAuthn login ceremony (start is rate-limited) → set session cookie
8. `/_gate/passkey/delete` (POST) → remove a stored passkey (requires session)
9. All other paths → check session cookie → if valid, streaming reverse proxy to `UPSTREAM`; if not, render login page via minijinja

### Key Components

- **Config**: loaded via figment (defaults → `hodor.toml` → env vars). Defined as a `Config` struct with serde.
- **AppState**: shared runtime state (config-derived values, rate limiter, HTTP client)
- **Session tokens**: `<unix_expiry>|<hmac_sha256(expiry)>` — signed with SECRET
- **TOTP 2FA**: hand-rolled RFC 6238 (HMAC-SHA1, 30s step, 6 digits, ±1 step skew) with an RFC 4648 base32 decoder, both covered by RFC test vectors. Enabled when `TOTP_SECRET` (base32) is set; applies to password login only — passkey login (user verification required) already counts as two factors
- **Rate limiter**: in-memory `HashMap<IpAddr, Vec<Instant>>` behind `Arc<Mutex<_>>`, 5 attempts per 60s per IP
- **Template system**: Jinja2 templates via minijinja. Built-in login template in `src/template.html`, error template in `src/error_template.html`, and passkey management template in `src/passkeys_template.html` (all embedded via `include_str!`). Custom login/error templates via `TEMPLATE`/`ERROR_TEMPLATE` config. Login variables: `title`, `show_error`, `passkeys_enabled`, `totp_enabled`. Error variables: `title`, `status_code`, `heading`, `message`. Passkeys page variables: `title`, `passkeys` (list of `{id, name, added_at}`).
- **Passkeys**: webauthn-rs. Enabled when `ORIGIN` is set (`RP_ID` optionally overrides the relying party ID derived from it). Registered credentials persist as JSON in `PASSKEYS_FILE` (default `passkeys.json`), written atomically via temp file + rename. All passkeys belong to one fixed user handle (shared identity). In-flight WebAuthn ceremony state lives in in-memory challenge maps with a 5-minute TTL and a 256-entry cap.
- **Proxy**: streaming (bodies are not buffered in memory), sets `X-Forwarded-For`/`X-Forwarded-Proto`, strips hop-by-hop headers

### Dependencies

- **HTTP**: tokio, axum, hyper, hyper-util, http, http-body-util
- **Crypto**: hmac, sha1 (TOTP), sha2, subtle, hex, rand
- **Passkeys**: webauthn-rs (pulls in openssl — the Dockerfile links it statically)
- **Config**: figment, serde
- **Templates**: minijinja
- **Serialization**: serde_json
- **Logging**: tracing, tracing-subscriber

No database, no ORM, no framework magic. (Passkeys persist to a single JSON file.)

## Configuration

Layered: defaults → `hodor.toml` → environment variables. See README.md for the full table.

Required: `password`/`PASSWORD`, `upstream`/`UPSTREAM`. Everything else has defaults.

## Build & Test

```sh
cargo build                        # debug build
cargo build --release              # release build
cargo clippy -- -D warnings        # lint
cargo fmt -- --check               # format check
```

Docker:

```sh
docker build -t hodor .
docker compose up                  # runs with traefik/whoami as example upstream
```

## CI/CD

- `.github/workflows/ci.yml` — cargo test + fmt + clippy + hadolint (on push/PR)
- `.github/workflows/bump-version.yml` — manual dispatch: bumps `Cargo.toml` version via `cargo set-version`, commits, and pushes `vX.Y.Z` tag
- `.github/workflows/release.yml` — triggered by `v*` tag: generates changelog via git-cliff (`cliff.toml`), builds multi-arch Docker image + pushes to ghcr.io, creates GitHub release with changelog
- `.github/workflows/pr-title.yml` — conventional commit PR title enforcement

## Code Conventions

- Single file (`src/main.rs`) + template (`src/template.html`) — keep it that way until it genuinely needs splitting
- No comments except for security protocol documentation and non-obvious behavior
- No `unwrap()` in request handlers — proper error handling with `?` or match
- `unwrap()` / `.expect()` OK in `main()` for fatal config errors
- No `unsafe`, no `#[allow(...)]`
