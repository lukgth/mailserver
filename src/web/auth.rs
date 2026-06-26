use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts, StatusCode},
    response::Response,
};
use log::{debug, error, info, warn};

use super::AppState;
use crate::web::errors::render_error_page;
use crate::fail2ban;

pub struct AuthAdmin {
    pub admin: crate::db::Admin,
}

// ── Login rate limiting ─────────────────────────────────────────────────────

const MAX_FAILURES: u32 = 5;
const WINDOW: Duration = Duration::from_secs(900); // 15 minutes
const BAN_DURATION: Duration = Duration::from_secs(900); // 15 min ban after exceeding

struct FailureRecord {
    count: u32,
    first_at: Instant,
    banned_until: Option<Instant>,
}

// ponytail: global lock is fine — single admin, low traffic
static LOGIN_FAILURES: LazyLock<Mutex<HashMap<IpAddr, FailureRecord>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn is_locked_out(ip: &IpAddr) -> bool {
    let mut map = LOGIN_FAILURES.lock().unwrap();
    if let Some(rec) = map.get_mut(ip) {
        let now = Instant::now();
        // If banned, check if ban expired
        if let Some(banned_until) = rec.banned_until {
            if now < banned_until {
                return true;
            }
            // Ban expired — reset
            map.remove(ip);
            return false;
        }
        // If outside the window, reset
        if now.duration_since(rec.first_at) > WINDOW {
            map.remove(ip);
            return false;
        }
        // Within window, check count
        rec.count >= MAX_FAILURES
    } else {
        false
    }
}

fn record_failure(ip: &IpAddr) {
    let mut map = LOGIN_FAILURES.lock().unwrap();
    let now = Instant::now();
    match map.get_mut(ip) {
        Some(rec) => {
            if now.duration_since(rec.first_at) > WINDOW {
                // Window expired, start fresh
                rec.count = 1;
                rec.first_at = now;
                rec.banned_until = None;
            } else if rec.count >= MAX_FAILURES {
                // Already at limit, extend ban
                rec.banned_until = Some(now + BAN_DURATION);
            } else {
                rec.count += 1;
                if rec.count >= MAX_FAILURES {
                    rec.banned_until = Some(now + BAN_DURATION);
                    warn!("[web] login rate limit exceeded for IP {}; banned for {}s", ip, BAN_DURATION.as_secs());
                }
            }
        }
        None => {
            map.insert(
                *ip,
                FailureRecord {
                    count: 1,
                    first_at: now,
                    banned_until: None,
                },
            );
        }
    }
}

fn clear_failures(ip: &IpAddr) {
    LOGIN_FAILURES.lock().unwrap().remove(ip);
}

/// Extract client IP from request headers (X-Forwarded-For, X-Real-IP) or socket address.
fn get_client_ip(parts: &Parts) -> IpAddr {
    // Check X-Forwarded-For (nginx sets this)
    if let Some(forwarded) = parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = forwarded.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    // Check X-Real-IP
    if let Some(real_ip) = parts.headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
            return ip;
        }
    }
    // Fall back to socket address from Axum ConnectInfo extension
    parts
        .extensions
        .get::<std::net::SocketAddr>()
        .map(|sa| sa.ip())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)))
}

fn rate_limited_response() -> Response {
    let body = render_error_page(
        StatusCode::TOO_MANY_REQUESTS,
        "Too Many Attempts",
        "Too many failed login attempts. Please wait a few minutes and try again.",
        "/",
        "Dashboard",
    );
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(axum::body::Body::from(body.0))
        .expect("Failed to build response")
}

// ── Auth extractor ──────────────────────────────────────────────────────────

fn unauthorized() -> Response {
    warn!("[web] unauthorized access attempt");
    let body = render_error_page(
        StatusCode::UNAUTHORIZED,
        "Unauthorized",
        "Valid admin credentials are required to reach this section.",
        "/",
        "Dashboard",
    );
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"Mailserver Admin\"")
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(axum::body::Body::from(body.0))
        .expect("Failed to build unauthorized response")
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthAdmin
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let ip = get_client_ip(parts);

        debug!("[web] authenticating request to {}", parts.uri);

        // Check rate limit before doing any work
        if is_locked_out(&ip) {
            warn!("[web] rate limited login attempt from {}", ip);
            return Err(rate_limited_response());
        }

        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                warn!("[web] missing Authorization header for {}", parts.uri);
                unauthorized()
            })?;

        // Bearer token authentication (for REST API)
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            let token = token.trim().to_string();
            let valid = app_state
                .blocking_db(move |db| db.verify_api_token(&token))
                .await;
            if !valid {
                warn!("[web] invalid Bearer token for {}", parts.uri);
                record_failure(&ip);
                fail2ban::record_web_auth_failure(&ip.to_string(), "bearer");
                return Err(unauthorized());
            }
            let admin = app_state
                .blocking_db(|db| db.get_first_admin())
                .await
                .ok_or_else(|| {
                    error!("[web] no admin found for Bearer token auth");
                    unauthorized()
                })?;
            info!("[web] Bearer token authentication succeeded");
            clear_failures(&ip);
            return Ok(AuthAdmin { admin });
        }

        if !auth_header.starts_with("Basic ") {
            warn!("[web] invalid Authorization scheme for {}", parts.uri);
            return Err(unauthorized());
        }

        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &auth_header[6..],
        )
        .map_err(|_| {
            warn!(
                "[web] failed to decode base64 credentials for {}",
                parts.uri
            );
            record_failure(&ip);
            fail2ban::record_web_auth_failure(&ip.to_string(), "unknown");
            unauthorized()
        })?;
        let credentials = String::from_utf8(decoded).map_err(|_| {
            warn!("[web] invalid UTF-8 in credentials for {}", parts.uri);
            record_failure(&ip);
            fail2ban::record_web_auth_failure(&ip.to_string(), "unknown");
            unauthorized()
        })?;
        let (username, password) = credentials.split_once(':').ok_or_else(|| {
            warn!("[web] malformed credentials (no colon) for {}", parts.uri);
            record_failure(&ip);
            fail2ban::record_web_auth_failure(&ip.to_string(), "unknown");
            unauthorized()
        })?;

        debug!("[web] auth attempt for username={}", username);

        let username_for_db = username.to_string();
        let admin = app_state
            .blocking_db(move |db| db.get_admin_by_username(&username_for_db))
            .await
            .ok_or_else(|| {
                warn!(
                    "[web] authentication failed — unknown username={}",
                    username
                );
                record_failure(&ip);
                fail2ban::record_web_auth_failure(&ip.to_string(), username);
                unauthorized()
            })?;

        if admin.totp_enabled {
            debug!(
                "[web] TOTP enabled for username={}, verifying password+TOTP",
                username
            );
            if password.len() < 6 {
                warn!(
                    "[web] authentication failed — password too short for TOTP for username={}",
                    username
                );
                record_failure(&ip);
                fail2ban::record_web_auth_failure(&ip.to_string(), username);
                return Err(unauthorized());
            }
            let (base_password, totp_code) = password.split_at(password.len() - 6);
            if !crate::auth::verify_password(base_password, &admin.password_hash) {
                warn!(
                    "[web] authentication failed — wrong password for username={}",
                    username
                );
                record_failure(&ip);
                fail2ban::record_web_auth_failure(&ip.to_string(), username);
                return Err(unauthorized());
            }
            let secret = admin.totp_secret.as_deref().ok_or_else(|| {
                error!(
                    "[web] TOTP enabled but no secret stored for username={}",
                    username
                );
                unauthorized()
            })?;
            if !crate::auth::verify_totp(secret, totp_code) {
                warn!(
                    "[web] authentication failed — invalid TOTP code for username={}",
                    username
                );
                record_failure(&ip);
                fail2ban::record_web_auth_failure(&ip.to_string(), username);
                return Err(unauthorized());
            }
        } else if !crate::auth::verify_password(password, &admin.password_hash) {
            warn!(
                "[web] authentication failed — wrong password for username={}",
                username
            );
            record_failure(&ip);
            fail2ban::record_web_auth_failure(&ip.to_string(), username);
            return Err(unauthorized());
        }

        info!("[web] authentication succeeded for username={}", username);
        clear_failures(&ip);
        Ok(AuthAdmin { admin })
    }
}
