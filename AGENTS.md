# Agents

## Project Overview

Hodor is a tiny Rust reverse proxy that gates any web app behind a single shared password. It runs as a Docker sidecar — no users, no database, no OAuth. One binary, one password, one login page.

## Architecture

Single-binary HTTP server built on axum + hyper. Everything lives in `src/main.rs`, with the default templates in `src/template.html` (login page) and `src/error_template.html` (error page).

### Request Flow

1. Request arrives at hodor
2. `/_gate/health` → bypass auth, return 200
3. Password missing? → render the setup page via minijinja
4. `/_gate/login` (POST) → if no password exists yet, validate + store it, set session cookie; otherwise rate-limit check → constant-time password compare → set session cookie
5. `/_gate/logout` → clear cookie, redirect
6. All other paths → check session cookie → if valid, streaming reverse proxy to `UPSTREAM`; if not, render login page via minijinja

### Key Components

- **Config**: loaded via figment (defaults → `hodor.toml` → env vars). Defined as a `Config` struct with serde.
- **AppState**: shared runtime state (config-derived values, bootstrap-aware password state, rate limiter, HTTP client)
- **Session tokens**: `<unix_expiry>|<hmac_sha256(expiry)>` — signed with SECRET
- **Brute-force protection**: in-memory `HashMap<IpAddr, LoginRecord>` behind `Arc<Mutex<_>>` — sliding-window rate limit (5 attempts / 60s per IP), escalating lockouts after 10 consecutive failures (60s doubling per failure, capped at 1h), 500ms delay on failed attempts, `Retry-After` on 429s, capped at 10k tracked IPs with oldest-entry eviction. Client IP is the TCP peer address, or the rightmost `X-Forwarded-For` entry when `TRUST_PROXY=true`
- **Template system**: Jinja2 templates via minijinja. Built-in login template in `src/template.html`, setup template in `src/setup_template.html`, and error template in `src/error_template.html` (all embedded via `include_str!`). Custom templates via `TEMPLATE`/`SETUP_TEMPLATE`/`ERROR_TEMPLATE`; extra CSS via `CUSTOM_CSS` (injected after the built-in styles, unescaped); `DISABLE_DEFAULT_CSS` drops the built-in styles entirely. Login and setup variables: `title`, `show_error`, `error_message`, `custom_css`, `disable_default_css`. Error variables: `title`, `status_code`, `heading`, `message`, `custom_css`, `disable_default_css`.
- **Proxy**: streaming (bodies are not buffered in memory), sets `X-Forwarded-For`/`X-Forwarded-Proto`, strips hop-by-hop headers

### Dependencies

- **HTTP**: tokio, axum, hyper, hyper-util, http, http-body-util
- **Crypto**: hmac, sha2, subtle, hex, rand
- **Config**: figment, serde
- **Templates**: minijinja
- **Logging**: tracing, tracing-subscriber

No database, no ORM, no framework magic.

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
