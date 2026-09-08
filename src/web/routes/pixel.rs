use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use log::{debug, info, warn};

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::web::forms::PixelQuery;
use crate::web::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/pixel", get(pixel_handler))
}

// ── Per-IP pixel rate limiting ──────────────────────────────────────────────
// In-memory sliding window (mirrors the LOGIN_FAILURES pattern in web/auth.rs):
// max PIXEL_MAX_PER_MIN requests per IP per minute, then HTTP 429. The map is
// bounded to PIXEL_MAX_ENTRIES keys; stale entries are evicted eagerly and an
// arbitrary entry is dropped when the cap is still reached.

const PIXEL_MAX_PER_MIN: usize = 30;
const PIXEL_WINDOW: Duration = Duration::from_secs(60);
const PIXEL_MAX_ENTRIES: usize = 10_000;

type PixelRateMap = HashMap<IpAddr, VecDeque<Instant>>;

static PIXEL_RATE_LIMITS: LazyLock<Mutex<PixelRateMap>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Sliding-window per-IP rate limiter. Returns `true` when the request is
/// allowed (and records it); `false` when the IP has exceeded the limit.
fn pixel_rate_allowed(ip: &IpAddr) -> bool {
    let now = Instant::now();
    let cutoff = now - PIXEL_WINDOW;
    let mut map = PIXEL_RATE_LIMITS.lock().unwrap();
    if map.len() >= PIXEL_MAX_ENTRIES {
        // Evict stale entries before dropping anything.
        map.retain(|_, times| {
            times.retain(|&t| t >= cutoff);
            !times.is_empty()
        });
    }
    if map.len() >= PIXEL_MAX_ENTRIES {
        // Still at capacity — evict one arbitrary entry (bounded memory).
        if let Some(k) = map.keys().next().copied() {
            map.remove(&k);
        }
    }
    let times = map.entry(*ip).or_default();
    times.retain(|&t| t >= cutoff);
    if times.len() >= PIXEL_MAX_PER_MIN {
        return false;
    }
    times.push_back(now);
    true
}

/// Truncate a string to `max` bytes at a character boundary.
fn truncate_at(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Mask the last segment of an IP address for privacy.
/// IPv4: `192.168.1.100` → `192.168.1.x`
/// IPv6: `2001:db8::1`   → `2001:db8::x`
fn mask_ip(ip: &str) -> String {
    if ip.contains(':') {
        // IPv6: replace everything after the last ':' with 'x'
        if let Some(pos) = ip.rfind(':') {
            return format!("{}:x", &ip[..pos]);
        }
    } else if ip.contains('.') {
        // IPv4: replace last octet with 'x'
        if let Some(pos) = ip.rfind('.') {
            return format!("{}.x", &ip[..pos]);
        }
    }
    ip.to_string()
}

async fn pixel_handler(
    State(state): State<AppState>,
    Query(params): Query<PixelQuery>,
    req: axum::http::Request<axum::body::Body>,
) -> Response {
    debug!(
        "[web] GET /pixel — pixel request id={}",
        if params.id.is_empty() {
            "(empty)"
        } else {
            &params.id
        }
    );

    // Per-IP sliding-window rate limit (applies to every pixel request).
    let (parts, _body) = req.into_parts();
    let client_ip = crate::web::auth::get_client_ip(&parts);
    if !pixel_rate_allowed(&client_ip) {
        warn!("[web] pixel rate limit exceeded for IP {}", client_ip);
        return (StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response();
    }

    if !params.id.is_empty() {
        // Mask last segment of IP for geo-location while preserving privacy
        let masked_ip = mask_ip(&client_ip.to_string());

        let user_agent = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        // Cap the stored user agent to bound log-row size.
        let user_agent = truncate_at(&user_agent, 256);

        let message_id = params.id.clone();

        // Only record opens for messages this server actually tracked; ignore
        // unknown ids with a 204 so scanners cannot populate the table.
        let db_message_id = message_id.clone();
        let known = state
            .blocking_db(move |db| db.tracked_message_exists(&db_message_id))
            .await;
        if !known {
            debug!("[web] pixel open for unknown message_id={}, ignoring", message_id);
            return StatusCode::NO_CONTENT.into_response();
        }

        let db_message_id = message_id.clone();
        let db_client_ip = masked_ip.clone();
        let db_user_agent = user_agent.clone();

        state
            .blocking_db(move |db| {
                db.record_pixel_open(&db_message_id, &db_client_ip, &db_user_agent)
            })
            .await;
        info!(
            "[web] pixel open recorded: message_id={}, client_ip={}, user_agent={}",
            message_id, masked_ip, user_agent
        );
    }

    let gif: &[u8] = &[
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff,
        0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
    ];

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/gif")],
        gif.to_vec(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::mask_ip;

    #[test]
    fn mask_ip_ipv4_last_octet() {
        assert_eq!(mask_ip("192.168.1.100"), "192.168.1.x");
        assert_eq!(mask_ip("10.0.0.1"), "10.0.0.x");
    }

    #[test]
    fn mask_ip_ipv6_last_group() {
        assert_eq!(mask_ip("2001:db8::1"), "2001:db8::x");
        assert_eq!(mask_ip("fe80::1"), "fe80::x");
        assert_eq!(mask_ip("::1"), "::x");
    }

    #[test]
    fn mask_ip_empty_unchanged() {
        assert_eq!(mask_ip(""), "");
    }
}
