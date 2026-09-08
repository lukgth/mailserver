use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use log::{info, warn};
use serde_json::Value;

use super::super::AppState;
use super::{account_email, get_session_state, JmapAuth};

// ── Well-known discovery (RFC 8620 §2) ───────────────────────────────────────

pub async fn well_known(State(state): State<AppState>) -> Json<Value> {
    let hostname = &state.hostname;
    let port = state.admin_port;
    let base = format!("http://{}:{}", hostname, port);

    Json(serde_json::json!({
        "apiUrl": format!("{}/jap", base),
        "sessionResource": format!("{}/jap/session", base),
    }))
}

// ── Auth login ────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct AuthLoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn auth_login(
    State(state): State<AppState>,
    Json(req): Json<AuthLoginRequest>,
) -> Response {
    let email_lower = req.email.trim().to_lowercase();

    // DAV-2: reject attempts while the account is inside its failure-lockout
    // window, before any further work.
    if crate::web::routes::webdav::dav_auth::is_locked(&email_lower) {
        warn!("[jmap] login locked out for {}", email_lower);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "type": "urn:ietf:params:jmap:error:rateLimit",
                "detail": "Too many failed login attempts"
            })),
        )
            .into_response();
    }

    let email_lower_clone = email_lower.clone();
    let account = state
        .blocking_db(move |db| db.get_jmap_account_by_email(&email_lower_clone))
        .await;

    // Unknown user, inactive account and wrong password all share one constant
    // error body, so the endpoint cannot be used to enumerate accounts.
    let Some(account) = account.filter(|a| a.active) else {
        crate::web::routes::webdav::dav_auth::record_failure(&email_lower);
        warn!("[jmap] auth failed for {}", email_lower);
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "type": "urn:ietf:params:jmap:error:unauthorized",
                "detail": "Invalid email or password"
            })),
        )
            .into_response();
    };

    if !crate::auth::verify_password(&req.password, &account.password_hash) {
        crate::web::routes::webdav::dav_auth::record_failure(&email_lower);
        warn!("[jmap] bad password for {}", email_lower);
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "type": "urn:ietf:params:jmap:error:unauthorized",
                "detail": "Invalid email or password"
            })),
        )
            .into_response();
    }

    // Success — clear any earlier failure marks for this account.
    crate::web::routes::webdav::dav_auth::clear(&email_lower);

    // Generate token
    let token = uuid::Uuid::new_v4().to_string();
    let token_clone = token.clone();
    let account_id = account.id;
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    state
        .blocking_db(move |db| {
            db.create_jmap_token(account_id, &token_clone, &now);
        })
        .await;

    info!("[jmap] token issued for {}", account_email(&account));

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "token": token,
            "accountId": account.id.to_string(),
        })),
    )
        .into_response()
}

// ── Session resource ──────────────────────────────────────────────────────────

pub async fn session_resource(
    auth: JmapAuth,
    State(state): State<AppState>,
) -> Json<Value> {
    let hostname = &state.hostname;
    let port = state.admin_port;
    let base = format!("http://{}:{}", hostname, port);
    let email = account_email(&auth.account);
    let account_id = auth.account_id;
    let aid = account_id.to_string();

    Json(serde_json::json!({
        "capabilities": {
            "urn:ietf:params:jmap:core": {
                "maxSizeUpload": 50000000,
                "maxConcurrentUpload": 4,
                "maxSizeRequest": 10000000,
                "maxConcurrentRequests": 4,
                "maxCallsInRequest": 16,
                "maxObjectsInGet": 500,
                "maxObjectsInSet": 0,
                "collationAlgorithms": ["i;ascii-numeric"]
            },
            "urn:ietf:params:jmap:mail": {
                "maxMailboxesPerEmail": 100,
                "maxMailboxDepth": 10,
                "maxSizeMailboxName": 200,
                "maxSizeAttachmentsPerEmail": 50000000,
                "emailSetSupports": [],
                "submissionSetSupports": []
            }
        },
        "accounts": {
            aid.clone(): {
                "name": email,
                "isPrimary": true,
                "isReadOnly": true,
                "accountCapabilities": {
                    "urn:ietf:params:jmap:mail": {}
                }
            }
        },
        "primaryAccounts": {
            "urn:ietf:params:jmap:mail": aid
        },
        "username": email,
        "apiUrl": format!("{}/jap", base),
        "downloadUrl": format!("{}/jap/download/{{accountId}}/{{blobId}}", base),
        "uploadUrl": format!("{}/jap/upload/{{accountId}}", base),
        "eventSourceUrl": format!("{}/jap/event", base),
        "state": get_session_state(&state, account_id).await,
    }))
}

// ── Blob download ────────────────────────────────────────────────────────────

pub async fn download_blob(
    auth: JmapAuth,
    State(_state): State<AppState>,
    Path((account_id, blob_id)): Path<(String, String)>,
) -> Response {
    // Verify account_id matches authenticated user
    if account_id != auth.account_id.to_string() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "type": "urn:ietf:params:jmap:error:forbidden",
                "detail": "Account mismatch"
            })),
        )
            .into_response();
    }

    // JMAP-1: blob_id is an email filename and must be a plain, safe path
    // component — reject traversal before any path is constructed.
    if !crate::web::routes::webmail::is_safe_path_component(&blob_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "type": "urn:ietf:params:jmap:error:invalidArguments",
                "detail": "Invalid blob id"
            })),
        )
            .into_response();
    }

    let maildir_base = super::maildir_path(
        auth.account.domain_name.as_deref().unwrap_or(""),
        &auth.account.username,
    );

    // Defense in depth: only serve files whose canonicalized path resolves
    // inside the account's maildir root (also blocks symlink escapes).
    let canon_base =
        std::fs::canonicalize(&maildir_base).unwrap_or_else(|_| std::path::PathBuf::from(&maildir_base));
    let base_prefix = format!("{}/", canon_base.display());

    // Search through all maildir folders for this filename
    let folders = super::scan_maildir_folders(&maildir_base);
    let mut file_path = None;

    for (dir_name, _) in &folders {
        let base = super::mailbox_dir(&maildir_base, &super::mailbox_id_from_dir(dir_name));
        for sub in &["cur", "new"] {
            let path = format!("{}/{}/{}", base, sub, blob_id);
            if !std::path::Path::new(&path).exists() {
                continue;
            }
            match std::fs::canonicalize(&path) {
                Ok(canon) => {
                    let canon_str = canon.to_string_lossy().to_string();
                    if canon_str == canon_base || canon_str.starts_with(&base_prefix) {
                        file_path = Some(canon_str);
                    }
                }
                Err(e) => warn!("[jmap] blob canonicalize error: {}", e),
            }
            if file_path.is_some() {
                break;
            }
        }
        if file_path.is_some() {
            break;
        }
    }

    match file_path {
        Some(path) => match tokio::fs::read(&path).await {
            Ok(data) => {
                // Try to detect Content-Type from the email
                let ct = "message/rfc822";
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, ct), (header::CONTENT_LENGTH, &data.len().to_string())],
                    data,
                )
                    .into_response()
            }
            Err(e) => {
                warn!("[jmap] blob read error: {}", e);
                (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "type": "urn:ietf:params:jmap:error:notFound",
                        "detail": "Blob not found"
                    })),
                )
                    .into_response()
            }
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "type": "urn:ietf:params:jmap:error:notFound",
                "detail": "Blob not found"
            })),
        )
            .into_response(),
    }
}
