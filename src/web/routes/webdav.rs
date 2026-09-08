use askama::Template;
use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use log::{error, info, warn};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use std::sync::LazyLock;

use crate::web::auth::AuthAdmin;
use crate::web::forms::WebDavSettingsForm;
use crate::web::AppState;

// ── DAV account-password rate limiting ──
//
// Shared lockout for WebDAV / CalDAV / CardDAV Basic auth: 5 failures for a
// given account within 15 minutes triggers a 15-minute ban. Sibling modules
// (caldav.rs, carddav.rs) reach it via
// `crate::web::routes::webdav::dav_auth::{is_locked, record_failure, clear}`.

pub mod dav_auth {
    use log::warn;
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    use std::time::{Duration, Instant};

    const MAX_FAILURES: u32 = 5;
    const WINDOW: Duration = Duration::from_secs(900); // 15 minutes
    const BAN_DURATION: Duration = Duration::from_secs(900); // 15 min ban after exceeding
    const MAX_ENTRIES: usize = 10_000;

    struct FailureRecord {
        count: u32,
        first_at: Instant,
        banned_until: Option<Instant>,
    }

    // ponytail: global lock is fine — DAV auth is low traffic
    static FAILURES: LazyLock<Mutex<HashMap<String, FailureRecord>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    /// Returns true when `key` is currently banned or has hit the failure limit
    /// inside the current window.
    pub fn is_locked(key: &str) -> bool {
        let mut map = FAILURES.lock().unwrap();
        let now = Instant::now();
        if let Some(rec) = map.get_mut(key) {
            // If banned, check if the ban expired
            if let Some(banned_until) = rec.banned_until {
                if now < banned_until {
                    return true;
                }
                // Ban expired — reset
                map.remove(key);
                return false;
            }
            // If outside the window, reset
            if now.duration_since(rec.first_at) > WINDOW {
                map.remove(key);
                return false;
            }
            // Within window, check count
            return rec.count >= MAX_FAILURES;
        }
        false
    }

    /// Record a failed authentication attempt for `key`.
    pub fn record_failure(key: &str) {
        let mut map = FAILURES.lock().unwrap();
        let now = Instant::now();
        match map.get_mut(key) {
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
                        warn!(
                            "[dav] auth rate limit exceeded for {}; banned for {}s",
                            key,
                            BAN_DURATION.as_secs()
                        );
                    }
                }
            }
            None => {
                // Keep the map bounded: evict expired entries first, then the
                // single oldest entry if we are still at capacity.
                if map.len() >= MAX_ENTRIES {
                    map.retain(|_, r| {
                        let expired = r
                            .banned_until
                            .map_or(false, |b| b <= now)
                            || now.duration_since(r.first_at) > WINDOW;
                        !expired
                    });
                    if map.len() >= MAX_ENTRIES {
                        if let Some(oldest) = map
                            .iter()
                            .min_by_key(|(_, r)| r.first_at)
                            .map(|(k, _)| k.clone())
                        {
                            map.remove(&oldest);
                        }
                    }
                }
                map.insert(
                    key.to_string(),
                    FailureRecord {
                        count: 1,
                        first_at: now,
                        banned_until: None,
                    },
                );
            }
        }
    }

    /// Clear any failure record for `key` after successful authentication.
    pub fn clear(key: &str) {
        FAILURES.lock().unwrap().remove(key);
    }
}

// ── WebDAV storage directory ──

// Serializes quota check → disk write → DB upsert so concurrent uploads cannot
// exceed the per-owner quota (TOCTOU guard).
static QUOTA_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

fn webdav_dir() -> &'static str {
    if std::path::Path::new("/var/mail").exists() {
        "/var/mail/webdav"
    } else {
        "./data/webdav"
    }
}

fn ensure_webdav_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(webdav_dir())
}

fn file_path(token: &str) -> std::path::PathBuf {
    std::path::Path::new(webdav_dir()).join(token)
}

// ── Templates ──

#[derive(Template)]
#[template(path = "webdav/list.html")]
struct ListTemplate<'a> {
    nav_active: &'a str,
    flash: Option<&'a str>,
    files: Vec<crate::db::WebDavFile>,
    webdav_enabled: bool,
    webdav_max_file_size_mb: i64,
    webdav_quota_mb: i64,
}

// ── WebDAV storage directory ──

pub async fn list(_auth: AuthAdmin, State(state): State<AppState>) -> Html<String> {
    info!("[web] GET /webdav — listing webdav files");
    let files = state.blocking_db(|db| db.list_webdav_files()).await;
    let webdav_enabled = state
        .blocking_db(|db| db.get_setting("webdav_enabled"))
        .await
        .map(|v| v != "false")
        .unwrap_or(true);
    let webdav_max_file_size_mb = state
        .blocking_db(|db| db.get_setting("webdav_max_file_size_mb"))
        .await
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50);
    let webdav_quota_mb = state
        .blocking_db(|db| db.get_setting("webdav_quota_mb"))
        .await
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);
    let tmpl = ListTemplate {
        nav_active: "WebDAV",
        flash: None,
        files,
        webdav_enabled,
        webdav_max_file_size_mb,
        webdav_quota_mb,
    };
    Html(tmpl.render().unwrap())
}

pub async fn update_settings(
    _auth: AuthAdmin,
    State(state): State<AppState>,
    Form(form): Form<WebDavSettingsForm>,
) -> Response {
    info!("[web] POST /webdav/settings — updating webdav settings");
    let enabled = form.webdav_enabled.is_some();
    let max_size = form.webdav_max_file_size_mb.unwrap_or(50);
    let quota = form.webdav_quota_mb.unwrap_or(0);

    let enabled_val = if enabled { "true" } else { "false" }.to_string();
    let max_size_val = max_size.to_string();
    let quota_val = quota.to_string();

    state
        .blocking_db(move |db| {
            db.set_setting("webdav_enabled", &enabled_val);
            db.set_setting("webdav_max_file_size_mb", &max_size_val);
            db.set_setting("webdav_quota_mb", &quota_val);
        })
        .await;

    info!(
        "[web] webdav settings updated: enabled={} max_size_mb={} quota_mb={}",
        enabled, max_size, quota
    );
    Redirect::to("/webdav").into_response()
}

pub async fn admin_delete_file(
    _auth: AuthAdmin,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Response {
    warn!("[web] POST /webdav/{}/delete — admin deleting file", id);
    let deleted = state.blocking_db(move |db| db.delete_webdav_file(id)).await;
    if let Some(f) = deleted {
        let path = file_path(&f.token);
        if let Err(e) = std::fs::remove_file(&path) {
            warn!("[web] could not remove webdav file on disk {:?}: {}", path, e);
        }
    }
    Redirect::to("/webdav").into_response()
}

// ── Basic Auth helper ──

fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = auth.strip_prefix("Basic ")?;
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encoded,
    )
    .ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (user, pass) = s.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

fn unauthorized_webdav() -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"WebDAV\""),
    );
    resp
}

fn require_webdav_auth(
    db: &crate::db::Database,
    headers: &HeaderMap,
) -> Result<(i64, String), Response> {
    let (email, password) = match parse_basic_auth(headers) {
        Some(creds) => creds,
        None => return Err(unauthorized_webdav()),
    };

    // Rate-limit account-password attempts before doing any bcrypt work
    if dav_auth::is_locked(&email) {
        warn!("[webdav] rate limited auth attempt for {}", email);
        return Err(unauthorized_webdav());
    }

    match db.get_account_for_webdav_auth(&email) {
        Some((account_id, hash)) if crate::auth::verify_password(&password, &hash) => {
            dav_auth::clear(&email);
            Ok((account_id, email))
        }
        _ => {
            dav_auth::record_failure(&email);
            warn!("[webdav] bad password for account: {}", email);
            Err(unauthorized_webdav())
        }
    }
}

// ── WebDAV XML helpers ──

fn propfind_xml_collection(href: &str, entries: &[crate::db::WebDavFile]) -> String {
    let mut buf = Vec::new();
    let mut writer = Writer::new_with_indent(&mut buf, b' ', 2);

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))
        .ok();

    let mut ms = BytesStart::new("D:multistatus");
    ms.push_attribute(("xmlns:D", "DAV:"));
    writer.write_event(Event::Start(ms)).ok();

    write_propfind_collection_entry(&mut writer, href);

    for f in entries {
        let file_href = format!("{}{}", href, f.filename);
        write_propfind_file_entry(&mut writer, &file_href, f);
    }

    writer
        .write_event(Event::End(BytesEnd::new("D:multistatus")))
        .ok();

    String::from_utf8(buf).unwrap_or_default()
}

fn propfind_xml_file(href: &str, file: &crate::db::WebDavFile) -> String {
    let mut buf = Vec::new();
    let mut writer = Writer::new_with_indent(&mut buf, b' ', 2);

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))
        .ok();

    let mut ms = BytesStart::new("D:multistatus");
    ms.push_attribute(("xmlns:D", "DAV:"));
    writer.write_event(Event::Start(ms)).ok();

    write_propfind_file_entry(&mut writer, href, file);

    writer
        .write_event(Event::End(BytesEnd::new("D:multistatus")))
        .ok();

    String::from_utf8(buf).unwrap_or_default()
}

fn write_propfind_collection_entry<W: std::io::Write>(writer: &mut Writer<W>, href: &str) {
    writer
        .write_event(Event::Start(BytesStart::new("D:response")))
        .ok();
    writer
        .write_event(Event::Start(BytesStart::new("D:href")))
        .ok();
    writer
        .write_event(Event::Text(BytesText::new(href)))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:href")))
        .ok();
    writer
        .write_event(Event::Start(BytesStart::new("D:propstat")))
        .ok();
    writer
        .write_event(Event::Start(BytesStart::new("D:prop")))
        .ok();
    writer
        .write_event(Event::Start(BytesStart::new("D:resourcetype")))
        .ok();
    writer
        .write_event(Event::Empty(BytesStart::new("D:collection")))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:resourcetype")))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:prop")))
        .ok();
    writer
        .write_event(Event::Start(BytesStart::new("D:status")))
        .ok();
    writer
        .write_event(Event::Text(BytesText::new("HTTP/1.1 200 OK")))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:status")))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:propstat")))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:response")))
        .ok();
}

fn write_propfind_file_entry<W: std::io::Write>(
    writer: &mut Writer<W>,
    href: &str,
    file: &crate::db::WebDavFile,
) {
    writer
        .write_event(Event::Start(BytesStart::new("D:response")))
        .ok();
    writer
        .write_event(Event::Start(BytesStart::new("D:href")))
        .ok();
    writer
        .write_event(Event::Text(BytesText::new(href)))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:href")))
        .ok();
    writer
        .write_event(Event::Start(BytesStart::new("D:propstat")))
        .ok();
    writer
        .write_event(Event::Start(BytesStart::new("D:prop")))
        .ok();
    writer
        .write_event(Event::Empty(BytesStart::new("D:resourcetype")))
        .ok();
    writer
        .write_event(Event::Start(BytesStart::new("D:displayname")))
        .ok();
    writer
        .write_event(Event::Text(BytesText::new(&file.filename)))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:displayname")))
        .ok();
    let size_str = file.size.to_string();
    writer
        .write_event(Event::Start(BytesStart::new("D:getcontentlength")))
        .ok();
    writer
        .write_event(Event::Text(BytesText::new(&size_str)))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:getcontentlength")))
        .ok();
    writer
        .write_event(Event::Start(BytesStart::new("D:getcontenttype")))
        .ok();
    writer
        .write_event(Event::Text(BytesText::new(&file.content_type)))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:getcontenttype")))
        .ok();
    writer
        .write_event(Event::Start(BytesStart::new("D:getlastmodified")))
        .ok();
    writer
        .write_event(Event::Text(BytesText::new(&file.updated_at)))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:getlastmodified")))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:prop")))
        .ok();
    writer
        .write_event(Event::Start(BytesStart::new("D:status")))
        .ok();
    writer
        .write_event(Event::Text(BytesText::new("HTTP/1.1 200 OK")))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:status")))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:propstat")))
        .ok();
    writer
        .write_event(Event::End(BytesEnd::new("D:response")))
        .ok();
}

// ── WebDAV endpoint ──
//
// All requests to /dav/{*path} land here.
// The `path` parameter is the part after "/dav/", e.g. "user@domain/" or "user@domain/file.txt".

pub async fn dav_handler(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    method: Method,
    request: axum::extract::Request,
) -> Response {
    // Check if WebDAV is enabled
    let enabled = state
        .blocking_db(|db| db.get_setting("webdav_enabled"))
        .await
        .map(|v| v != "false")
        .unwrap_or(true);

    if !enabled {
        return (StatusCode::SERVICE_UNAVAILABLE, "WebDAV is disabled").into_response();
    }

    // Handle OPTIONS — no auth required
    if method == Method::OPTIONS {
        let mut resp = Response::new(Body::empty());
        *resp.status_mut() = StatusCode::OK;
        resp.headers_mut().insert(
            header::ALLOW,
            HeaderValue::from_static(
                "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL",
            ),
        );
        resp.headers_mut().insert(
            HeaderName::from_static("dav"),
            HeaderValue::from_static("1"),
        );
        resp.headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        return resp;
    }

    // Parse the path parameter: "user@domain" or "user@domain/filename"
    let (owner, filename): (String, Option<String>) =
        if let Some(idx) = path.find('/') {
            let o = path[..idx].to_string();
            let f = path[idx + 1..].to_string();
            (o, if f.is_empty() { None } else { Some(f) })
        } else {
            (path.clone(), None)
        };

    if owner.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing user in path").into_response();
    }

    // Authenticate
    let headers_clone = headers.clone();
    let auth_result = state
        .blocking_db(move |db| require_webdav_auth(db, &headers_clone))
        .await;

    let (account_id, authed_owner) = match auth_result {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Enforce that the authenticated user can only access their own space
    if authed_owner.to_lowercase() != owner.to_lowercase() {
        return (StatusCode::FORBIDDEN, "Access denied").into_response();
    }

    let method_str = method.as_str();

    match (method_str, &filename) {
        // PROPFIND on collection (directory listing)
        ("PROPFIND", None) => {
            let owner_c = owner.clone();
            let files = state
                .blocking_db(move |db| db.list_webdav_files_for_owner(&owner_c))
                .await;
            let href = format!("/dav/{}/", owner);
            let xml = propfind_xml_collection(&href, &files);
            let mut resp = Response::new(Body::from(xml));
            *resp.status_mut() = StatusCode::MULTI_STATUS;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/xml; charset=utf-8"),
            );
            resp.headers_mut().insert(
                HeaderName::from_static("dav"),
                HeaderValue::from_static("1"),
            );
            resp
        }

        // PROPFIND on a specific file
        ("PROPFIND", Some(fname)) => {
            let fname = fname.clone();
            let owner_c = owner.clone();
            let file = state
                .blocking_db(move |db| db.get_webdav_file_by_owner_and_name(&owner_c, &fname))
                .await;
            match file {
                Some(f) => {
                    let href = format!("/dav/{}/{}", owner, f.filename);
                    let xml = propfind_xml_file(&href, &f);
                    let mut resp = Response::new(Body::from(xml));
                    *resp.status_mut() = StatusCode::MULTI_STATUS;
                    resp.headers_mut().insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/xml; charset=utf-8"),
                    );
                    resp.headers_mut().insert(
                        HeaderName::from_static("dav"),
                        HeaderValue::from_static("1"),
                    );
                    resp
                }
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }

        // GET/HEAD — download file
        ("GET" | "HEAD", Some(fname)) => {
            let fname = fname.clone();
            let owner_c = owner.clone();
            let file = state
                .blocking_db(move |db| db.get_webdav_file_by_owner_and_name(&owner_c, &fname))
                .await;
            match file {
                Some(f) => serve_file(&f, method_str == "HEAD").await,
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }

        // PUT — upload file
        ("PUT", Some(fname)) => {
            let fname = fname.clone();
            let max_size_mb = state
                .blocking_db(|db| db.get_setting("webdav_max_file_size_mb"))
                .await
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(50);
            let quota_mb = state
                .blocking_db(|db| db.get_setting("webdav_quota_mb"))
                .await
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);

            let body_bytes = match axum::body::to_bytes(
                request.into_body(),
                (max_size_mb * 1024 * 1024) as usize + 1,
            )
            .await
            {
                Ok(b) => b,
                Err(_) => {
                    return (StatusCode::PAYLOAD_TOO_LARGE, "File too large").into_response()
                }
            };

            if body_bytes.len() as i64 > max_size_mb * 1024 * 1024 {
                return (StatusCode::PAYLOAD_TOO_LARGE, "File exceeds maximum size")
                    .into_response();
            }

            let content_type = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();

            // Serialize quota check → disk write → DB upsert so concurrent
            // uploads cannot exceed the per-owner quota (TOCTOU guard).
            let _quota_guard = QUOTA_LOCK.lock().await;

            // Check quota
            if quota_mb > 0 {
                let owner_q = owner.clone();
                let current_usage = state
                    .blocking_db(move |db| db.count_webdav_usage_for_owner(&owner_q))
                    .await;
                if current_usage + body_bytes.len() as i64 > quota_mb * 1024 * 1024 {
                    return (StatusCode::INSUFFICIENT_STORAGE, "Quota exceeded").into_response();
                }
            }

            if let Err(e) = ensure_webdav_dir() {
                error!("[webdav] failed to create storage dir: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            // Reuse existing token if file already exists
            let owner_c = owner.clone();
            let fname_c = fname.clone();
            let existing = state
                .blocking_db(move |db| db.get_webdav_file_by_owner_and_name(&owner_c, &fname_c))
                .await;
            let token = existing
                .as_ref()
                .map(|f| f.token.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

            let fpath = file_path(&token);
            let size = body_bytes.len() as i64;

            if let Err(e) = std::fs::write(&fpath, &body_bytes) {
                error!("[webdav] failed to write file {:?}: {}", fpath, e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            let owner_c = owner.clone();
            let fname_c = fname.clone();
            let ct = content_type.clone();
            let token_c = token.clone();
            let is_new = existing.is_none();
            let result = state
                .blocking_db(move |db| {
                    db.upsert_webdav_file(
                        Some(account_id),
                        &owner_c,
                        &fname_c,
                        &ct,
                        size,
                        &token_c,
                    )
                })
                .await;

            match result {
                Ok(_) => {
                    info!("[webdav] PUT {}/{} size={}", owner, fname, size);
                    if is_new {
                        StatusCode::CREATED.into_response()
                    } else {
                        StatusCode::NO_CONTENT.into_response()
                    }
                }
                Err(e) => {
                    error!("[webdav] db upsert failed: {}", e);
                    let _ = std::fs::remove_file(&fpath);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }

        // DELETE — remove file
        ("DELETE", Some(fname)) => {
            let fname = fname.clone();
            let owner_c = owner.clone();
            let fname_log = fname.clone();
            let owner_log = owner.clone();
            let deleted = state
                .blocking_db(move |db| {
                    db.delete_webdav_file_by_owner_and_name(&owner_c, &fname)
                })
                .await;
            match deleted {
                Some(f) => {
                    let fpath = file_path(&f.token);
                    if let Err(e) = std::fs::remove_file(&fpath) {
                        warn!("[webdav] could not remove file {:?}: {}", fpath, e);
                    }
                    info!("[webdav] DELETE {}/{}", owner_log, fname_log);
                    StatusCode::NO_CONTENT.into_response()
                }
                None => StatusCode::NOT_FOUND.into_response(),
            }
        }

        // MKCOL on collection root — collection auto-exists per authenticated user
        ("MKCOL", None) => StatusCode::CREATED.into_response(),

        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

async fn serve_file(file: &crate::db::WebDavFile, head_only: bool) -> Response {
    let fpath = file_path(&file.token);
    match std::fs::read(&fpath) {
        Ok(data) => {
            let ct = file.content_type.parse::<HeaderValue>().unwrap_or(
                HeaderValue::from_static("application/octet-stream"),
            );
            let disp = format!("attachment; filename=\"{}\"", file.filename);
            let disp_val = disp
                .parse::<HeaderValue>()
                .unwrap_or(HeaderValue::from_static("attachment"));
            let body = if head_only {
                Body::empty()
            } else {
                Body::from(data)
            };
            let mut resp = Response::new(body);
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert(header::CONTENT_TYPE, ct);
            resp.headers_mut()
                .insert(header::CONTENT_LENGTH, file.size.to_string().parse().unwrap_or(HeaderValue::from_static("0")));
            resp.headers_mut()
                .insert(header::CONTENT_DISPOSITION, disp_val);
            resp
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// ── Mozilla FileLink API ──

/// POST /filelink/upload — multipart upload, returns JSON with public URL
pub async fn filelink_upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let enabled = state
        .blocking_db(|db| db.get_setting("webdav_enabled"))
        .await
        .map(|v| v != "false")
        .unwrap_or(true);

    if !enabled {
        return (StatusCode::SERVICE_UNAVAILABLE, "WebDAV/FileLink is disabled").into_response();
    }

    let auth_result = state
        .blocking_db(move |db| require_webdav_auth(db, &headers))
        .await;

    let (account_id, owner) = match auth_result {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let max_size_mb = state
        .blocking_db(|db| db.get_setting("webdav_max_file_size_mb"))
        .await
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50);

    let quota_mb = state
        .blocking_db(|db| db.get_setting("webdav_quota_mb"))
        .await
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0);

    let max_bytes = (max_size_mb * 1024 * 1024) as usize;

    let mut field_count = 0usize;
    while let Ok(Some(mut field)) = multipart.next_field().await {
        field_count += 1;
        if field_count > 10 {
            return (StatusCode::PAYLOAD_TOO_LARGE, "Too many fields").into_response();
        }

        let field_name = field.name().unwrap_or("").to_string();
        if field_name != "file" && field_name != "attachment" {
            continue;
        }

        let original_filename = field.file_name().unwrap_or("upload").to_string();
        let content_type = field
            .content_type()
            .unwrap_or("application/octet-stream")
            .to_string();

        // Stream the field in chunks, aborting with 413 as soon as the size
        // limit is exceeded — never buffer an unbounded upload in memory.
        let mut data: Vec<u8> = Vec::new();
        let mut too_large = false;
        loop {
            let chunk = match field.chunk().await {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) => {
                    error!("[filelink] failed to read upload chunk: {}", e);
                    return (StatusCode::BAD_REQUEST, "Failed to read file").into_response();
                }
            };
            if data.len() + chunk.len() > max_bytes {
                too_large = true;
                break;
            }
            data.extend_from_slice(&chunk);
        }
        if too_large {
            return (StatusCode::PAYLOAD_TOO_LARGE, "File exceeds maximum size").into_response();
        }

        // Serialize quota check → disk write → DB upsert so concurrent
        // uploads cannot exceed the per-owner quota (TOCTOU guard).
        let _quota_guard = QUOTA_LOCK.lock().await;

        if quota_mb > 0 {
            let owner_q = owner.clone();
            let current_usage = state
                .blocking_db(move |db| db.count_webdav_usage_for_owner(&owner_q))
                .await;
            if current_usage + data.len() as i64 > quota_mb * 1024 * 1024 {
                return (StatusCode::INSUFFICIENT_STORAGE, "Quota exceeded").into_response();
            }
        }

        if let Err(e) = ensure_webdav_dir() {
            error!("[filelink] failed to create storage dir: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        let owner_c = owner.clone();
        let fname_c = original_filename.clone();
        let existing = state
            .blocking_db(move |db| db.get_webdav_file_by_owner_and_name(&owner_c, &fname_c))
            .await;
        let token = existing
            .as_ref()
            .map(|f| f.token.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let fpath = file_path(&token);
        let size = data.len() as i64;

        if let Err(e) = std::fs::write(&fpath, &data) {
            error!("[filelink] failed to write file: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        let owner_c = owner.clone();
        let fname_c = original_filename.clone();
        let ct = content_type.clone();
        let token_c = token.clone();
        let result = state
            .blocking_db(move |db| {
                db.upsert_webdav_file(Some(account_id), &owner_c, &fname_c, &ct, size, &token_c)
            })
            .await;

        match result {
            Ok(_) => {
                info!(
                    "[filelink] upload {} for {} size={}",
                    original_filename, owner, size
                );
                let download_url = format!("/filelink/download/{}", token);
                let json = serde_json::json!({
                    "url": download_url,
                    "id": token,
                });
                let mut resp = Response::new(Body::from(json.to_string()));
                *resp.status_mut() = StatusCode::OK;
                resp.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                return resp;
            }
            Err(e) => {
                error!("[filelink] db upsert failed: {}", e);
                let _ = std::fs::remove_file(&fpath);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }

    (StatusCode::BAD_REQUEST, "No file field found in upload").into_response()
}

/// GET /filelink/download/:token — public download (no auth required)
pub async fn filelink_download(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Response {
    let file = state
        .blocking_db(move |db| db.get_webdav_file_by_token(&token))
        .await;
    match file {
        Some(f) => serve_file(&f, false).await,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// DELETE /filelink/delete/:token — authenticated delete
pub async fn filelink_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let auth_result = state
        .blocking_db(move |db| require_webdav_auth(db, &headers))
        .await;

    let (_account_id, owner) = match auth_result {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let token_c = token.clone();
    let file = state
        .blocking_db(move |db| db.get_webdav_file_by_token(&token_c))
        .await;

    match file {
        Some(f) if f.owner.to_lowercase() == owner.to_lowercase() => {
            let fid = f.id;
            let deleted = state
                .blocking_db(move |db| db.delete_webdav_file(fid))
                .await;
            if let Some(df) = deleted {
                let fpath = file_path(&df.token);
                if let Err(e) = std::fs::remove_file(&fpath) {
                    warn!("[filelink] could not remove file {:?}: {}", fpath, e);
                }
            }
            info!("[filelink] deleted token={}", token);
            StatusCode::NO_CONTENT.into_response()
        }
        Some(_) => (StatusCode::FORBIDDEN, "Access denied").into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Public routes (no admin auth required)
pub fn public_routes() -> axum::Router<AppState> {
    use axum::routing::{any, delete, get, post};
    axum::Router::new()
        .route("/dav/*path", any(dav_handler))
        .route("/filelink/upload", post(filelink_upload))
        .route("/filelink/download/{token}", get(filelink_download))
        .route("/filelink/delete/{token}", delete(filelink_delete))
}
