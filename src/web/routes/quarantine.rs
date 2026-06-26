use askama::Template;
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use log::{debug, info, warn};
use serde::Deserialize;

use crate::web::auth::AuthAdmin;
use crate::web::AppState;

// ── Templates ──

#[derive(Template)]
#[template(path = "quarantine/list.html")]
struct QuarantineListTemplate<'a> {
    nav_active: &'a str,
    flash: Option<&'a str>,
    emails: Vec<QuarantineEmail>,
}

struct QuarantineEmail {
    id: String,
    subject: String,
    sender: String,
    recipient: String,
    score: String,
    date: String,
    size: String,
}

#[derive(Template)]
#[template(path = "quarantine/detail.html")]
struct QuarantineDetailTemplate<'a> {
    nav_active: &'a str,
    flash: Option<&'a str>,
    id: &'a str,
    subject: String,
    sender: String,
    recipient: String,
    score: String,
    date: String,
    headers: String,
    body: String,
}

// ── Forms ──

#[derive(Deserialize)]
pub struct ActionForm {
    pub action: String, // "release", "delete", "deny"
}

// ── Helpers ──

fn rspamd_url() -> String {
    std::env::var("RSPAMD_URL").unwrap_or_else(|_| "http://rspamd:11334".to_string())
}

fn fetch_quarantine_list() -> Vec<QuarantineEmail> {
    let url = format!("{}/quarantine", rspamd_url());
    match reqwest::blocking::get(&url) {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<Vec<serde_json::Value>>() {
                Ok(items) => items
                    .iter()
                    .map(|item| QuarantineEmail {
                        id: item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        subject: item.get("subject").and_then(|v| v.as_str()).unwrap_or("(no subject)").to_string(),
                        sender: item.get("from").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        recipient: item.get("to").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                        score: format!("{:.1}", item.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0)),
                        date: item.get("date").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        size: item.get("size").and_then(|v| v.as_i64()).map(|s| format!("{} KB", s / 1024)).unwrap_or("0 KB".to_string()),
                    })
                    .collect(),
                Err(e) => {
                    warn!("[quarantine] failed to parse Rspamd response: {}", e);
                    vec![]
                }
            }
        }
        Ok(resp) => {
            warn!("[quarantine] Rspamd returned status: {}", resp.status());
            vec![]
        }
        Err(e) => {
            warn!("[quarantine] failed to connect to Rspamd: {}", e);
            vec![]
        }
    }
}

fn fetch_quarantine_detail(id: &str) -> Option<(String, String)> {
    let url = format!("{}/quarantine/{}", rspamd_url(), id);
    match reqwest::blocking::get(&url) {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<serde_json::Value>() {
                Ok(data) => {
                    let headers = data.get("headers").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let body = data.get("body").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    Some((headers, body))
                }
                Err(e) => {
                    warn!("[quarantine] failed to parse detail: {}", e);
                    None
                }
            }
        }
        _ => None,
    }
}

fn quarantine_action(id: &str, action: &str) -> bool {
    let url = format!("{}/quarantine/{}/{}", rspamd_url(), id, action);
    match reqwest::blocking::Client::new()
        .post(&url)
        .send()
    {
        Ok(resp) if resp.status().is_success() => true,
        Ok(resp) => {
            warn!("[quarantine] action {} on {} returned: {}", action, id, resp.status());
            false
        }
        Err(e) => {
            warn!("[quarantine] failed to {} {}: {}", action, id, e);
            false
        }
    }
}

// ── Handlers ──

pub async fn list(
    _auth: AuthAdmin,
    State(_state): State<AppState>,
) -> Response {
    debug!("[web] GET /quarantine — listing quarantined emails");
    let emails = fetch_quarantine_list();
    let tmpl = QuarantineListTemplate {
        nav_active: "Quarantine",
        flash: None,
        emails,
    };
    Html(tmpl.render().unwrap()).into_response()
}

pub async fn detail(
    _auth: AuthAdmin,
    State(_state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    debug!("[web] GET /quarantine/{} — viewing quarantined email", id);

    // Fetch from list to get metadata
    let emails = fetch_quarantine_list();
    let meta = emails.iter().find(|e| e.id == id);

    let (headers, body) = fetch_quarantine_detail(&id).unwrap_or_default();

    let tmpl = QuarantineDetailTemplate {
        nav_active: "Quarantine",
        flash: None,
        id: &id,
        subject: meta.map(|e| e.subject.clone()).unwrap_or_default(),
        sender: meta.map(|e| e.sender.clone()).unwrap_or_default(),
        recipient: meta.map(|e| e.recipient.clone()).unwrap_or_default(),
        score: meta.map(|e| e.score.clone()).unwrap_or_else(|| "0.0".to_string()),
        date: meta.map(|e| e.date.clone()).unwrap_or_default(),
        headers,
        body,
    };
    Html(tmpl.render().unwrap()).into_response()
}

pub async fn action(
    _auth: AuthAdmin,
    State(_state): State<AppState>,
    Path(id): Path<String>,
    Form(form): Form<ActionForm>,
) -> Response {
    info!("[web] POST /quarantine/{}/{} — quarantined email action", id, form.action);
    // Validate action
    if !["release", "delete", "deny"].contains(&form.action.as_str()) {
        warn!("[web] invalid quarantine action: {}", form.action);
        return Redirect::to("/quarantine").into_response();
    }
    let success = quarantine_action(&id, &form.action);
    if success {
        Redirect::to("/quarantine").into_response()
    } else {
        Redirect::to("/quarantine").into_response()
    }
}
