mod auth;
mod errors;
mod forms;
pub mod routes;

use axum::http::{header, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, get_service};
use axum::Router;
use log::{debug, info, warn};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::services::ServeDir;

use crate::web::errors::status_response;



/// Represents one active IMAP-IDLE (SSE) connection from the webmail client.
#[derive(Clone, Serialize)]
pub struct ImapIdleSession {
    pub id: String,
    pub account_id: i64,
    pub username: String,
    pub domain: String,
    pub folder: String,
    pub connected_at: String,
    pub last_ping_at: String,
    /// Unix timestamp of when the session was opened; used to compute duration.
    pub connected_at_secs: i64,
    /// Signals the idle polling task to exit when set to `true`.
    #[serde(skip)]
    pub shutdown: Arc<AtomicBool>,
}

/// Shared in-memory registry of active IMAP IDLE sessions.
pub type ImapIdleRegistry = Arc<Mutex<HashMap<String, ImapIdleSession>>>;

// ── MCP rate-limit and anomaly-detection constants ────────────────────────────

/// Maximum number of MCP calls allowed per 60-second sliding window.
pub const MCP_RATE_LIMIT_PER_MIN: usize = 60;
/// Maximum destructive tool calls (`send_email`, `delete_email`) per 60-second window.
pub const MCP_DESTRUCTIVE_RATE_LIMIT_PER_MIN: usize = 10;
/// Number of consecutive failures that triggers an anomaly webhook.
pub const MCP_ANOMALY_CONSECUTIVE_FAILURES: u32 = 5;

// ── MCP in-process guard (rate limiter + anomaly detector) ───────────────────

/// Shared, in-memory guard for the MCP endpoint.
/// Enforces per-key sliding-window rate limits and detects anomalous patterns.
pub struct McpGuard {
    /// Per-key rate-limit and anomaly state (60-second sliding window per key).
    keys: HashMap<String, McpGuardState>,
}

/// Per-key rate-limit state.
struct McpGuardState {
    /// Timestamps of all MCP calls in the last 60 seconds.
    call_times: VecDeque<Instant>,
    /// Timestamps of destructive tool calls in the last 60 seconds.
    destructive_times: VecDeque<Instant>,
    /// Consecutive call failures; reset to 0 on any success.
    consecutive_failures: u32,
}

impl McpGuard {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Access (creating if needed) the state bucket for `key`.
    fn state(&mut self, key: &str) -> &mut McpGuardState {
        self.keys.entry(key.to_string()).or_insert_with(|| McpGuardState {
            call_times: VecDeque::new(),
            destructive_times: VecDeque::new(),
            consecutive_failures: 0,
        })
    }

    /// Return the current consecutive-failure count for `key` (for testing / diagnostics).
    #[allow(dead_code)]
    pub fn consecutive_failures(&self, key: &str) -> u32 {
        self.keys
            .get(key)
            .map(|s| s.consecutive_failures)
            .unwrap_or(0)
    }

    /// Evict entries outside the 60-second sliding window for `key`.
    /// Drops the key entirely once its state is empty so short-lived keys do
    /// not accumulate in the map.
    fn evict_old(&mut self, key: &str) {
        let cutoff = Instant::now() - Duration::from_secs(60);
        let empty = {
            let Some(state) = self.keys.get_mut(key) else {
                return;
            };
            while state.call_times.front().map(|&t| t < cutoff).unwrap_or(false) {
                state.call_times.pop_front();
            }
            while state
                .destructive_times
                .front()
                .map(|&t| t < cutoff)
                .unwrap_or(false)
            {
                state.destructive_times.pop_front();
            }
            state.call_times.is_empty()
                && state.destructive_times.is_empty()
                && state.consecutive_failures == 0
        };
        if empty {
            self.keys.remove(key);
        }
    }

    /// Check rate limits for `key` and, if allowed, record the call.
    /// Returns `Some(reason)` if a limit is exceeded (call is NOT recorded).
    /// Returns `None` and records the timestamp if the call is allowed.
    pub fn check_and_record(&mut self, key: &str, is_destructive: bool) -> Option<String> {
        self.evict_old(key);
        let state = self.state(key);
        if state.call_times.len() >= MCP_RATE_LIMIT_PER_MIN {
            return Some(format!(
                "Rate limit exceeded: more than {} MCP calls per minute",
                MCP_RATE_LIMIT_PER_MIN
            ));
        }
        if is_destructive && state.destructive_times.len() >= MCP_DESTRUCTIVE_RATE_LIMIT_PER_MIN {
            return Some(format!(
                "Destructive rate limit exceeded: more than {} send/delete operations per minute",
                MCP_DESTRUCTIVE_RATE_LIMIT_PER_MIN
            ));
        }
        let now = Instant::now();
        state.call_times.push_back(now);
        if is_destructive {
            state.destructive_times.push_back(now);
        }
        None
    }

    /// Record the outcome of a processed call for `key`.
    /// Returns `Some(reason)` if the consecutive-failure threshold is reached.
    pub fn record_outcome(&mut self, key: &str, success: bool) -> Option<String> {
        let state = self.state(key);
        if success {
            state.consecutive_failures = 0;
            None
        } else {
            state.consecutive_failures += 1;
            if state.consecutive_failures >= MCP_ANOMALY_CONSECUTIVE_FAILURES {
                Some(format!(
                    "Anomaly detected: {} consecutive MCP call failures",
                    state.consecutive_failures
                ))
            } else {
                None
            }
        }
    }
}

// ── CSRF double-submit cookie middleware ──────────────────────────────────────
//
// On every response: ensure a `csrf_token` cookie is set (SameSite=Strict).
// On POST/PUT/DELETE: validate that the form field `_csrf_token` matches
// the cookie value. This prevents cross-site form forgery even with
// HTTP Basic Auth, because the attacker cannot read the cookie from
// another origin.
const CSRF_COOKIE: &str = "csrf_token";
const CSRF_FIELD: &str = "_csrf_token";

/// Generate a short random hex token (16 bytes = 32 hex chars).
fn generate_csrf_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..16).map(|_| format!("{:02x}", rng.gen::<u8>())).collect()
}

/// Extract CSRF token from request cookie.
fn csrf_token_from_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|c| {
            let c = c.trim();
            c.strip_prefix("csrf_token=").map(|v| v.to_string())
        })
}

/// CSRF middleware: sets cookie on response, validates on mutation requests.
pub async fn csrf_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let method = req.method().clone();
    let cookie_token = csrf_token_from_cookie(req.headers());

    // For POST/PUT/DELETE, validate the CSRF token
    if method == Method::POST || method == Method::PUT || method == Method::DELETE {
        if let Some(cookie_val) = &cookie_token {
            // Extract X-CSRF-Token header before consuming request
            let header_token = req
                .headers()
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let (parts, body) = req.into_parts();
            let bytes = match axum::body::to_bytes(body, 1024 * 64).await {
                Ok(b) => b,
                Err(_) => {
                    return (StatusCode::BAD_REQUEST, "Bad request").into_response();
                }
            };

            // Only parse the form body for form-encoded or multipart content types.
            // JSON API calls (Content-Type: application/json) pass the token via
            // the X-CSRF-Token header and must not be forced to include a form field.
            let ct = parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let is_form = ct.starts_with("application/x-www-form-urlencoded")
                || ct.starts_with("multipart/form-data");

            let form_token = if method == Method::POST && is_form {
                let parsed: Vec<(String, String)> =
                    form_urlencoded::parse(&bytes).into_owned().collect();
                parsed
                    .into_iter()
                    .find(|(k, _)| k == CSRF_FIELD)
                    .map(|(_, v)| v)
            } else {
                None
            };

            let submitted = form_token.or(header_token);
            match &submitted {
                Some(t) if crate::db::constant_time_eq(t.as_bytes(), cookie_val.as_bytes()) => {
                    // Valid — reconstruct request with the original body.
                    // Use from_parts (NOT Request::builder) so request extensions
                    // are preserved; axum stores matched path parameters there, and
                    // dropping them causes Path extractors to fail with
                    // "No paths parameters found for matched route".
                    let req = axum::http::Request::from_parts(parts, axum::body::Body::from(bytes));
                    let mut response = next.run(req).await;
                    ensure_csrf_cookie(&mut response, &cookie_token);
                    return response;
                }
                _ => {
                    warn!("[csrf] token mismatch — rejecting mutation request");
                    return (StatusCode::FORBIDDEN, "CSRF token mismatch").into_response();
                }
            }
        } else {
            // No CSRF cookie — request is from a cookie-less client. CSRF
            // attacks work by making the browser attach same-origin cookies, so
            // a request that carries no token cookie can only be exploited if
            // it also needs no credentials the attacker lacks.
            //
            // 1. API/DAV clients authenticate via an Authorization header
            //    (Basic/Bearer) instead of a cookie — not vulnerable to
            //    cookie-based CSRF, pass through unchanged.
            // 2. Public endpoints (registration, unsubscribe, pixel, BIMI,
            //    autoconfig discovery, well-known) are reached without cookies
            //    and do not mutate private state, pass through unchanged.
            // 3. Every other cookie-less mutation is rejected: it can be
            //    forged cross-origin with no cookie and no credentials.
            let has_basic_or_bearer_auth = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(|v| {
                    let scheme = v.trim_start().split_whitespace().next().unwrap_or("");
                    scheme.eq_ignore_ascii_case("Basic")
                        || scheme.eq_ignore_ascii_case("Bearer")
                })
                .unwrap_or(false);

            if !has_basic_or_bearer_auth {
                let path = req.uri().path();
                const PUBLIC_PREFIXES: &[&str] = &[
                    "/register",
                    "/unsubscribe",
                    "/pixel",
                    "/bimi/",
                    "/mail/config-v1.1.xml",
                    "/.well-known/",
                ];
                let is_public = PUBLIC_PREFIXES.iter().any(|p| path.starts_with(p));
                if !is_public {
                    warn!(
                        "[csrf] rejecting cookie-less mutation without credentials: {} {}",
                        method, path
                    );
                    return (StatusCode::FORBIDDEN, "CSRF protection: missing CSRF token")
                        .into_response();
                }
            }
        }
    }

    // For GET and other safe methods, just ensure cookie exists and continue
    let mut response = next.run(req).await;
    ensure_csrf_cookie(&mut response, &cookie_token);
    response
}

/// Set the CSRF cookie if not already present.
fn ensure_csrf_cookie(response: &mut Response, existing: &Option<String>) {
    if existing.is_none() {
        let token = generate_csrf_token();
        let cookie_val = format!("{}={}; Path=/; SameSite=Strict", CSRF_COOKIE, token);
        if let Ok(val) = HeaderValue::from_str(&cookie_val) {
            response.headers_mut().append(header::SET_COOKIE, val);
        }
    }
}

// ── Shared State ──

#[derive(Clone)]
pub struct AppState {
    pub db: crate::db::Database,
    pub hostname: String,
    pub admin_port: u16,
    /// Shared rate-limiter and anomaly detector for the MCP endpoint.
    pub mcp_guard: Arc<Mutex<McpGuard>>,
    /// Registry of active webmail IMAP-IDLE (SSE) sessions.
    pub idle_registry: ImapIdleRegistry,
}

impl AppState {
    pub async fn blocking_db<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&crate::db::Database) -> R + Send + 'static,
        R: Send + 'static,
    {
        let db = self.db.clone();
        // Use std::thread instead of tokio::task::spawn_blocking to avoid "runtime within runtime" panic
        // because the synchronous postgres crate uses its own internal runtime which conflicts with
        // tokio's blocking thread pool context.
        let (tx, rx) = tokio::sync::oneshot::channel();

        std::thread::spawn(move || {
            let result = f(&db);
            let _ = tx.send(result);
        });

        rx.await.expect("Database thread panicked or was dropped")
    }
}

// ── Server ──

pub async fn start_server(state: AppState) {
    let port = state.admin_port;

    info!("[web] initializing admin web server on port {}", port);

    let static_dir = find_static_dir();

    let pixel_routes = routes::pixel::routes();
    let bimi_routes = routes::bimi::routes();
    let unsubscribe_routes = routes::unsubscribe::public_routes();
    let webdav_routes = routes::webdav::public_routes();
    let registration_routes = routes::registration_routes();
    let jmap_routes = routes::jmap::jmap_routes();
    let auth_routes = routes::auth_routes();

    let static_routes: Router<AppState> = match static_dir {
        Some(ref dir) => {
            info!("[web] serving static files from {}", dir);
            Router::new().nest_service("/static", get_service(ServeDir::new(dir)))
        }
        None => {
            info!("[web] no static directory found, using embedded static files");
            Router::new()
                .route("/static/style.css", axum::routing::get(embedded_style_css))
                .route("/static/desktop.css", axum::routing::get(embedded_desktop_css))
        }
    };

    let app = Router::new()
        .merge(pixel_routes)
        .merge(bimi_routes)
        .merge(unsubscribe_routes)
        .merge(webdav_routes)
        .merge(registration_routes)
        .merge(jmap_routes)
        .merge(static_routes)
        // Thunderbird autoconfig — MUST be before auth_routes (no auth required)
        .route("/mail/config-v1.1.xml", get(routes::autoconfig::autoconfig))
        .route("/.well-known/autoconfig/mail/config-v1.1.xml", get(routes::autoconfig::autoconfig))
        .merge(auth_routes)
        // CalDAV protocol handler — handles all HTTP methods on /caldav/{email}/...
        .route("/caldav/*path", axum::routing::any(routes::caldav::protocol_handler))
        // RFC 6764 well-known redirect for CalDAV auto-discovery
        .route(
            "/.well-known/caldav",
            axum::routing::any(|| async {
                axum::response::Redirect::permanent("/caldav/")
            }),
        )
        // CardDAV protocol handler — handles all HTTP methods on /carddav/{email}/...
        .route("/carddav/*path", axum::routing::any(routes::carddav::protocol_handler))
        // RFC 6764 well-known redirect for CardDAV auto-discovery
        .route(
            "/.well-known/carddav",
            axum::routing::any(|| async {
                axum::response::Redirect::permanent("/carddav/")
            }),
        )
        .fallback(handle_not_found)
        .layer(
            // CORS: allow same-origin requests only
            CorsLayer::new()
                .allow_origin(tower_http::cors::AllowOrigin::mirror_request())
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION]),
        )
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .with_state(state)
        .layer(axum::middleware::from_fn(csrf_middleware));

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind address {}: {}", addr, e));
    info!("[web] admin dashboard listening on {}", addr);
    axum::serve(listener, app).await.expect("Server error");
}

async fn handle_not_found(uri: Uri) -> Response {
    let message = format!("No page exists at {}", uri.path());
    status_response(
        StatusCode::NOT_FOUND,
        "Page not found",
        &message,
        "/",
        "Dashboard",
    )
}

fn find_static_dir() -> Option<String> {
    let candidates: Vec<String> = {
        let mut v = vec![
            "/app/static".to_string(),
            "static".to_string(),
        ];
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                v.push(dir.join("static").to_string_lossy().into_owned());
            }
        }
        v
    };
    candidates.into_iter().find(|p| std::path::Path::new(p).is_dir())
}

async fn embedded_style_css() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../static/style.css"),
    )
}

async fn embedded_desktop_css() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../static/desktop.css"),
    )
}

pub(crate) async fn regen_configs(state: &AppState) {
    info!("[web] regenerating mail service configs");
    let db = state.db.clone();
    let hostname = state.hostname.clone();
    // spawn_blocking runs in a dedicated OS thread outside the tokio runtime,
    // so the sync postgres client is safe to call there (no nested runtime panic).
    // We await the handle so callers know configs are written before we return.
    if let Err(e) = tokio::task::spawn_blocking(move || {
        crate::config::generate_all_configs(&db, &hostname);
    })
    .await
    {
        warn!("[web] regen_configs thread panicked: {:?}", e);
    }
}

/// Validate a webhook/outbound URL for SSRF safety.
///
/// Rules:
/// - Must parse as an absolute URL (`reqwest::Url`).
/// - Scheme must be `https`. The only `http` URLs accepted are
///   `http://127.0.0.1` and `http://localhost` (loopback, reserved for local
///   testing/tooling).
/// - The host must resolve via the system resolver; EVERY resolved address
///   must be a public, routable address. Loopback, private (RFC 1918),
///   link-local (169.254.0.0/16, fe80::/10), CGNAT (100.64.0.0/10),
///   benchmarking (198.18.0.0/15), IPv6 ULA (fc00::/7), `::1`, IPv4-mapped
///   variants and unspecified addresses are rejected.
/// - Obfuscated IP literal host forms (pure-integer decimal such as
///   `2130706433`, and `0x`/`0o`/`0b` hex/octal/binary literals) are rejected,
///   as is any host containing characters other than `[A-Za-z0-9.-:]`.
pub fn validate_outbound_url(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    // Hosts must be plain DNS names, dotted IPv4 or colon-separated IPv6.
    // Anything else (userinfo tricks, IDN escapes, etc.) is rejected.
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
    {
        return false;
    }
    if is_obfuscated_ip_literal(host) {
        return false;
    }

    // Loopback exception: http://127.0.0.1 and http://localhost, used by
    // tests and local tooling, bypass the address checks entirely.
    let loopback_exception = host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost")
        || host == "::1";

    if parsed.scheme() == "https" {
        // falls through to address checks
    } else if parsed.scheme() == "http" && loopback_exception {
        return true;
    } else {
        return false;
    }

    // Resolve the host and reject if ANY resolved address is non-public
    // (defends against DNS-rebinding style attacks).
    let port = parsed.port().unwrap_or(443);
    let Ok(addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    for addr in addrs {
        if ip_is_blocked(addr.ip()) {
            return false;
        }
    }
    true
}

/// True when `host` is an obfuscated IP literal (decimal/octal/hex/binary)
/// that DNS might interpret as an address — e.g. `2130706433` (127.0.0.1),
/// `0x7f000001`, `017700000001`.
fn is_obfuscated_ip_literal(host: &str) -> bool {
    // Pure decimal integer form.
    if host.parse::<u128>().is_ok() {
        return true;
    }
    // Hex/octal/binary integer forms — only when the whole host is a bare
    // number (a dotted host is a domain name).
    let rest = host
        .strip_prefix("0x")
        .or_else(|| host.strip_prefix("0X"))
        .or_else(|| host.strip_prefix("0o"))
        .or_else(|| host.strip_prefix("0O"))
        .or_else(|| host.strip_prefix("0b"))
        .or_else(|| host.strip_prefix("0B"));
    let Some(rest) = rest else {
        return false;
    };
    if rest.is_empty() || rest.contains('.') || rest.contains(':') {
        return false;
    }
    match host.get(..2) {
        Some("0x") | Some("0X") => rest.chars().all(|c| c.is_ascii_hexdigit()),
        Some("0o") | Some("0O") => rest.chars().all(|c| matches!(c, '0'..='7')),
        _ => rest.chars().all(|c| matches!(c, '0'..='1')),
    }
}

/// True when `ip` is a non-public address that outbound HTTP must never reach.
fn ip_is_blocked(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private() || v4.is_link_local() {
                return true;
            }
            let o = v4.octets();
            // 100.64.0.0/10 — Carrier-Grade NAT (CGNAT)
            if o[0] == 100 && (o[1] & 0xC0) == 0x40 {
                return true;
            }
            // 198.18.0.0/15 — benchmarking range (RFC 2544)
            if o[0] == 198 && (o[1] & 0xFE) == 0x12 {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            // IPv4-mapped IPv6 (::ffff:a.b.c.d) inherits the v4 rules.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_is_blocked(IpAddr::V4(v4));
            }
            let segs = v6.segments();
            // fc00::/7 — unique local addresses (ULA)
            if segs[0] & 0xFE00 == 0xFC00 {
                return true;
            }
            // fe80::/10 — IPv6 link-local (IPv4 counterpart: 169.254.0.0/16)
            if segs[0] & 0xFFC0 == 0xFE80 {
                return true;
            }
            false
        }
    }
}

/// Truncate `s` to at most `max_len` bytes without splitting a UTF-8 char.
fn truncate_utf8(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut end = max_len;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

/// Fire a webhook notification for a system activity event.
///
/// This sends a POST request with a JSON payload to the configured webhook URL.
/// The call is non-blocking — it spawns a background thread so the HTTP response
/// to the admin is not delayed by the webhook delivery.
///
/// `event` — short event identifier (e.g. "domain.created", "account.deleted")
/// `details` — a JSON-serialisable value with event-specific information
pub(crate) fn fire_webhook(state: &AppState, event: &str, details: serde_json::Value) {
    let db = state.db.clone();
    let event = event.to_string();
    let details = details;

    // All DB access runs on the spawned thread to avoid "Cannot start a runtime
    // from within a runtime" — the sync postgres::Client creates its own tokio
    // runtime internally and panics if called from within an existing one.
    std::thread::spawn(move || {
        let webhook_url = db.get_setting("webhook_url").unwrap_or_default();
        if webhook_url.is_empty() {
            return;
        }

        // Security: validate webhook URL (https-only, no internal/private targets)
        if !validate_outbound_url(&webhook_url) {
            warn!("[webhook] rejecting unsafe webhook URL: {}", webhook_url);
            return;
        }

        let timestamp = chrono::Utc::now().to_rfc3339();
        let payload = serde_json::json!({
            "event": event,
            "timestamp": timestamp,
            "details": details,
        });
        let request_body = payload.to_string();

        debug!("[webhook] firing {} to {}", event, webhook_url);
        let start = std::time::Instant::now();

        let (response_status, response_body, error) = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            // Never follow redirects: a redirect target must satisfy the same
            // SSRF checks as the original URL.
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(client) => match client.post(&webhook_url).json(&payload).send() {
                Ok(resp) => {
                    let status = resp.status().as_u16() as i32;
                    let body = resp.text().unwrap_or_default();
                    let body_truncated = truncate_utf8(&body, 2048);
                    info!(
                        "[webhook] {} delivered to {} status={}",
                        event, webhook_url, status
                    );
                    (Some(status), body_truncated, String::new())
                }
                Err(e) => {
                    warn!(
                        "[webhook] {} delivery failed to {}: {}",
                        event, webhook_url, e
                    );
                    (None, String::new(), e.to_string())
                }
            },
            Err(e) => {
                warn!("[webhook] failed to build HTTP client: {}", e);
                (None, String::new(), e.to_string())
            }
        };

        let duration_ms = start.elapsed().as_millis() as i64;

        // Log the webhook execution (best-effort)
        db.log_webhook(
            &webhook_url,
            &request_body,
            response_status,
            &response_body,
            &error,
            duration_ms,
            &event,
            "",
        );
    });
}

/// Fire a webhook using a Database reference directly (safe for background threads — no tokio runtime).
pub(crate) fn fire_webhook_with_db(db: &crate::db::Database, event: &str, details: serde_json::Value) {
    let webhook_url = db.get_setting("webhook_url").unwrap_or_default();
    if webhook_url.is_empty() { return; }
    // Security: validate webhook URL (https-only, no internal/private targets)
    if !validate_outbound_url(&webhook_url) {
        warn!("[webhook] rejecting unsafe webhook URL: {}", webhook_url);
        return;
    }
    let event = event.to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let payload = serde_json::json!({ "event": event, "timestamp": timestamp, "details": details });
    let request_body = payload.to_string();
    debug!("[webhook] firing {} to {}", event, webhook_url);
    let start = std::time::Instant::now();
    let (response_status, response_body, error) = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        // Never follow redirects: a redirect target must satisfy the same
        // SSRF checks as the original URL.
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => match client.post(&webhook_url).json(&payload).send() {
            Ok(resp) => {
                let status = resp.status().as_u16() as i32;
                let body = resp.text().unwrap_or_default();
                let body_truncated = truncate_utf8(&body, 2048);
                (status, body_truncated, String::new())
            }
            Err(e) => (-1, String::new(), e.to_string()),
        },
        Err(e) => (-1, String::new(), e.to_string()),
    };
    let duration_ms = start.elapsed().as_millis() as u64;
    if error.is_empty() {
        info!("[webhook] {} delivered (status={}) in {}ms", event, response_status, duration_ms);
    } else {
        warn!("[webhook] {} failed (status={}, error={}) in {}ms", event, response_status, error, duration_ms);
    }
    db.log_webhook(&webhook_url, &request_body, Some(response_status), &response_body, &error, duration_ms as i64, &event, "");
}
