# AGENTS.md — Mailserver

**Workspace:** `/d/projects/mailserver`

## Stack

| Layer | Technology |
|-------|-----------|
| Language | Rust 2021 edition |
| Web framework | Axum 0.7 |
| Async runtime | Tokio 1.x (full features) |
| Templates | Askama 0.12 (compile-time, `templates/`) |
| Database | PostgreSQL 16 via `postgres` crate (sync `Arc<Mutex<Client>>`) |
| Auth | bcrypt (`bcrypt` crate), TOTP 2FA, HMAC-SHA1 tokens |
| Mail libs | `lettre` (SMTP), `mailparse` (parsing), `russh` (SSH provisioning) |
| Container | Alpine 3.21 + Postfix + Dovecot + OpenDKIM + OpenSSL |
| Build | `cargo build --release` (multi-stage Docker) |
| CI | GitHub Actions (`.github/workflows/`) + Gitea (`.gitea/workflows/`) |

## Structure

```
src/
├── main.rs              # Entry point: subcommand dispatch (serve/filter/seed/genconfig/gencerts/provision/reset-password)
├── auth.rs              # Password hashing (bcrypt), HMAC token generation/verification, TOTP
├── config.rs            # Generates Postfix/Dovecot/OpenDKIM configs from templates/ into /etc/
├── db.rs                # All DB models (structs) and query methods on Database (Arc<Mutex<Client>>)
├── fail2ban.rs          # fail2ban log watcher (spawns thread, tails /var/log/mail.log)
├── filter.rs            # Postfix content filter (injects tracking pixels, footers, unsubscribe links)
├── provision.rs         # SSH auto-provisioner (deploys to remote VPS via russh)
└── web/
    ├── mod.rs           # AppState, Router assembly, start_server(), McpGuard, ImapIdleRegistry
    ├── auth.rs          # AuthAdmin extractor (session cookie → admin lookup)
    ├── errors.rs        # render_error_page(), status_response() helpers
    ├── forms.rs         # Form structs (DomainForm, AccountForm, AliasForm, etc.) — #[derive(Deserialize)]
    └── routes/
        ├── mod.rs       # auth_routes() + registration_routes() — all Axum route definitions
        ├── dashboard.rs, domains.rs, accounts.rs, aliases.rs, forwarding.rs, ...
        ├── api_email.rs, api_soap.rs, api_docs.rs   # REST/SOAP/MCP API endpoints
        ├── webmail.rs, imap_idle.rs                  # Built-in webmail (IMAP IDLE via SSE)
        ├── caldav.rs, carddav.rs, webdav.rs          # DAV servers
        ├── jmap/                                     # JMAP protocol (core, email, mailbox, thread)
        └── pixel.rs, tracking.rs, dmarc.rs, fail2ban.rs, ...

migrations/             # Numbered SQL schema files (001_initial_schema.sql → 020_jmap.sql)
templates/              # Askama HTML templates for admin dashboard
  ├── config/           # Postfix/Dovecot/OpenDKIM config templates (rendered by config.rs)
static/                 # CSS (style.css, desktop.css)
```

## Commands

| Action | Command |
|--------|---------|
| Build | `cargo build --release` |
| Build (Docker) | `docker compose build` or `docker build -t mailserver .` |
| Run locally | `MAILSERVER serve` (needs DATABASE_URL, HOSTNAME env vars) |
| Run (Docker) | `docker compose up -d` |
| Test (integration) | `./test-mailserver.sh --host localhost --username testuser --domain example.com` |
| DB migrations | Run automatically on first start via `entrypoint.sh` |
| Generate configs | `mailserver genconfig` |
| Generate certs | `mailserver gencerts` |
| Seed admin | `mailserver seed` (uses SEED_USER/SEED_PASS env vars) |

**No unit test suite.** The only test is `test-mailserver.sh` (integration, shell-based, runs against a live server).

## Conventions

- **Binary subcommands**: `main.rs` dispatches on `args[1]` — `serve`, `filter`, `seed`, `reset-password`, `genconfig`, `gencerts`, `provision`. Not a library.
- **Route pattern**: Each feature gets its own file in `src/web/routes/`. Handlers are `async fn` taking `State<AppState>` + `AuthAdmin` extractor + optional `Path`/`Query`/`Form` extractors.
- **Template rendering**: `#[derive(Template)]` with `#[template(path = "...")]`, rendered via `.render().expect(...)`, wrapped in `Html(...)`.
- **Forms**: Plain structs with `#[derive(Deserialize)]` in `forms.rs`. Axum `Form<T>` extractor.
- **DB access**: `Database` wraps `Arc<Mutex<Client>>`. Methods take `&self`, acquire lock, run sync queries. **Not async DB.** All models derive `Clone + Serialize`.
- **Error handling**: Use `errors::status_response(status, title, message, back_url, back_label)` for error pages. Use `log::error!()` for server-side logging. No `anyhow`/`thiserror` — bare `Result` with `expect()` or explicit `process::exit()`.
- **Config generation**: `config.rs` reads template files from `templates/config/`, renders them with Postfix/Dovecot variables, writes to `/etc/`. Templates are plain text with `{VARIABLE}` placeholders (not Askama).
- **Logging**: `env_logger` with `log` macros. Prefixed: `[main]`, `[filter]`, `[seed]`, `[config]`, etc.
- **No formatter/linter configured.** Code style is straightforward Rust — no rustfmt.toml, no clippy config.
- **Env vars**: All config via environment (see `.env.example`). DATABASE_URL, HOSTNAME, ADMIN_PORT, SEED_USER, SEED_PASS, PIXEL_BASE_URL.

## Key Files

| File | Role |
|------|------|
| `src/main.rs` | Subcommand dispatch — `serve` starts Axum, `filter` runs content filter, `seed` creates admin |
| `src/db.rs` | All DB models + query methods. Single source of truth for schema. ~2000+ lines. |
| `src/config.rs` | Postfix/Dovecot/OpenDKIM config generation. Writes to `/etc/` at startup. |
| `src/web/mod.rs` | AppState definition, Router assembly, `start_server()`, IMAP IDLE registry |
| `src/web/routes/mod.rs` | All Axum route definitions — add new routes here |
| `src/web/routes/domains.rs` | Example route file — shows the pattern: view models, handlers, template rendering |
| `src/web/errors.rs` | Error page rendering helpers |
| `src/web/forms.rs` | All form structs for POST handlers |
| `entrypoint.sh` | Docker entrypoint — runs migrations, seeds admin, starts Postfix/Dovecot, launches binary |
| `migrations/` | SQL schema — add new migrations as `NNN_description.sql` |

## What to Avoid

- **Don't add an async DB driver.** The project uses `postgres` (sync) behind `Arc<Mutex>`. Switching to `sqlx`/`tokio-postgres` is a large refactor with no clear benefit at current scale.
- **Don't add `anyhow`/`thiserror`.** Error handling is intentionally simple — `expect()`, `process::exit()`, log macros.
- **Don't add a formatter config** unless asked. The codebase has none.
- **Don't refactor `db.rs` into multiple files** unless it exceeds ~3k lines. It's one file by design.
- **Don't add unit tests to route handlers.** The project uses integration tests only (`test-mailserver.sh`).
- **Don't change the template system.** Askama for HTML, plain `{VAR}` for Postfix/Dovecot config templates. Both work, don't mix them.
- **Don't add dependencies without checking if stdlib or existing crates cover it.** The dependency list is already large.
- **New routes go in `src/web/routes/`** — one file per feature, registered in `routes/mod.rs`.
- **New DB schema changes go in `migrations/`** — numbered sequentially, applied automatically by `entrypoint.sh`.
- **This binary runs as Postfix content filter too** (`mailserver filter`). Don't add heavy dependencies or startup work to the filter path.
- **Templates live in `templates/`** (HTML) and `templates/config/` (Postfix/Dovecot). Don't mix.

## Notes

- **Single binary, multiple roles**: The same binary serves the admin dashboard, runs as Postfix content filter, generates configs, seeds users, and provisions remote servers. Entry point is `main.rs` with subcommand dispatch.
- **No WASM, no frontend build step.** Static CSS only. HTML is server-rendered via Askama.
- **Docker image ships Postfix + Dovecot + OpenDKIM + the Rust binary.** The `entrypoint.sh` orchestrates all services.
- **WebDAV/CalDAV/CardDAV are built in** (Rust handlers), not external services.
- **JMAP support** exists in `src/web/routes/jmap/` — relatively new, follow existing patterns there.
- **MCP endpoint** at `/mcp` — Model Context Protocol for AI assistant integration. Has rate limiting and anomaly detection.
- **The `provision` subcommand** uses SSH (russh) to deploy to remote VPS. It's self-contained in `provision.rs`.
- **Registration** is per-domain (`/register/:domain`), controlled by `registration_enabled` flag on each domain.
- **Existing copilot instructions** at `.github/copilot-instructions.md` contain Postfix/Dovecot architecture details — useful context for mail-related changes.
