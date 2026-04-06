# Agents

## Project Overview

Hodor is a tiny Rust reverse proxy that gates any web app behind a single shared password. It runs as a Docker sidecar — no users, no database, no OAuth. One binary, one password, one login page.

## Architecture

Single-binary HTTP server built on axum + hyper. Everything lives in `src/main.rs`.

### Request Flow

1. Request arrives at hodor
2. `/_gate/health` → bypass auth, return 200
3. `/_gate/login` (POST) → rate-limit check → constant-time password compare → set session cookie
4. `/_gate/logout` → clear cookie, redirect
5. All other paths → check session cookie → if valid, streaming reverse proxy to `UPSTREAM`; if not, return login page HTML

### Key Components

- **AppState**: shared config (password, template, secret, upstream, rate limiter, session settings)
- **Session tokens**: `<unix_expiry>|<hmac_sha256(expiry)>` — signed with SECRET env var
- **Rate limiter**: in-memory `HashMap<IpAddr, Vec<Instant>>` behind `Arc<Mutex<_>>`, 5 attempts per 60s per IP
- **Template system**: built-in HTML with `__TITLE__` placeholder and `display:none;` → `display:block;` error toggle. Custom HTML via `TEMPLATE` env var, loaded at startup.
- **Proxy**: streaming (bodies are not buffered in memory), sets `X-Forwarded-For`/`X-Forwarded-Proto`, strips hop-by-hop headers

### Dependencies

Minimal. stdlib + tokio/axum/hyper for HTTP, hmac/sha2/subtle for crypto, tracing for logging. No database, no ORM, no framework magic.

## Configuration

All env vars. See README.md for the full table.

Required: `PASSWORD`, `UPSTREAM`. Everything else has defaults.

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
- `.github/workflows/release.yml` — Docker build + push to ghcr.io on `v*` tag
- `.github/workflows/pr-title.yml` — conventional commit PR title enforcement

## Code Conventions

- Single file (`src/main.rs`) — keep it that way until it genuinely needs splitting
- No comments except for security protocol documentation and non-obvious behavior
- No `unwrap()` in request handlers — proper error handling with `?` or match
- `unwrap()` is OK in `main()` for fatal config errors
- No `unsafe`, no `#[allow(...)]`
