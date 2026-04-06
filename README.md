# hodor

[![MIT License](https://img.shields.io/github/license/michidk/hodor)](https://choosealicense.com/licenses/mit/) [![CI](https://github.com/michidk/hodor/actions/workflows/ci.yml/badge.svg)](https://github.com/michidk/hodor/actions/workflows/ci.yml)

A tiny reverse proxy that holds the door — put it in front of any app to gate access behind a single shared password. No users, no database, no OAuth. Just one password and a login page.

## Features

- Single shared password — no user accounts, no database
- Clean dark-themed login page (or bring your own)
- Runs as a Docker sidecar in front of any web app
- HMAC-SHA256 signed session cookies
- Streaming reverse proxy (handles large uploads/downloads without buffering)
- Constant-time password comparison
- Per-IP rate limiting on login (5 attempts / 60s)
- Structured logging (compact or JSON)
- Health check endpoint for container orchestrators
- Graceful shutdown on SIGTERM
- Zero config files — everything via environment variables
- Built with Rust, runs from a `scratch` image (~5MB)

## Quick Start

```yaml
# docker-compose.yml
services:
  gate:
    image: ghcr.io/michidk/hodor:latest
    ports:
      - "8080:8080"
    environment:
      PASSWORD: "changeme"
      UPSTREAM: "http://app:80"
      SECRET: "replace-with-openssl-rand-hex-32"
    depends_on:
      - app

  app:
    image: traefik/whoami
```

```sh
docker compose up
```

Open `http://localhost:8080` — you'll see the login page. Enter the password, and you're proxied through to the app.

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PASSWORD` | yes | | The shared password |
| `UPSTREAM` | yes | | Backend URL to proxy to (e.g. `http://app:3000`) |
| `SECRET` | no | random | Cookie signing key. Set this to persist sessions across restarts |
| `LISTEN` | no | `:8080` | Listen address |
| `TITLE` | no | `Password Required` | Login page heading |
| `TEMPLATE` | no | built-in | Path to a custom HTML login page |
| `SESSION_TTL` | no | `86400` | Session duration in seconds (default: 24h) |
| `SECURE_COOKIE` | no | `false` | Set `true` to add the `Secure` flag to cookies (requires HTTPS) |
| `LOG_FORMAT` | no | `compact` | Log output format: `compact` or `json` |
| `RUST_LOG` | no | `info` | Log level filter (e.g. `debug`, `hodor=trace`) |

## How It Works

```
Request → hodor
  ├─ /_gate/health → 200 ok (bypass auth)
  ├─ Has valid session cookie? → Reverse proxy to UPSTREAM
  └─ No cookie? → Show login page
       └─ POST /_gate/login
            ├─ Rate limited? → 429
            ├─ Password correct? → Set cookie, redirect back
            └─ Wrong? → Show login page with error
```

### Reserved Paths

- `/_gate/login` — login form submission (POST) / redirect to gate (GET)
- `/_gate/logout` — clears session cookie
- `/_gate/health` — returns `ok` (for liveness/readiness probes)

All other paths are proxied to the upstream.

### Proxy Behavior

- Streams request and response bodies without buffering (safe for large files)
- Sets `X-Forwarded-For` and `X-Forwarded-Proto` headers on proxied requests
- Strips hop-by-hop headers (Connection, Transfer-Encoding, etc.)
- Forwards the upstream's `Host` header

## Custom Login Page

Hodor ships with a built-in dark-themed login page. To use your own, set `TEMPLATE` to the path of an HTML file:

```yaml
environment:
  TEMPLATE: /etc/hodor/login.html
volumes:
  - ./my-login.html:/etc/hodor/login.html:ro
```

### Template Requirements

Your custom HTML must include:

1. A form that POSTs to `/_gate/login` with a `password` field and a `redirect` hidden field:

   ```html
   <form method="post" action="/_gate/login">
     <input type="hidden" name="redirect" value="/">
     <input name="password" type="password" required>
     <button type="submit">Continue</button>
   </form>
   ```

2. An error element with `display:none;` in its inline style (hodor flips this to `display:block;` on wrong password):

   ```html
   <div style="display:none;">Wrong password.</div>
   ```

3. (Optional) Use `__TITLE__` anywhere in the HTML — it gets replaced with the `TITLE` env var value at startup.

4. (Optional) JavaScript to capture the current URL into the redirect field:

   ```html
   <script>
     document.querySelector('input[name="redirect"]').value =
       window.location.pathname + window.location.search;
   </script>
   ```

## Building from Source

```sh
cargo build --release
```

```sh
PASSWORD=secret UPSTREAM=http://localhost:3000 ./target/release/hodor
```

## Docker

Build locally:

```sh
docker build -t hodor .
docker run -e PASSWORD=secret -e UPSTREAM=http://host.docker.internal:3000 -p 8080:8080 hodor
```

### Health Checks

```yaml
services:
  gate:
    image: ghcr.io/michidk/hodor:latest
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8080/_gate/health"]
      interval: 10s
      timeout: 2s
      retries: 3
```

Note: since hodor runs from `scratch`, `wget`/`curl` aren't available in the image. Use Docker's native health check or an external probe against `/_gate/health`.

## License

[MIT](LICENSE)
