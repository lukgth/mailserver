use askama::Template;
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect},
    Form,
};
use log::info;
use serde::Deserialize;

use crate::web::auth::AuthAdmin;
use crate::web::AppState;

// ── Forms ──

#[derive(Deserialize)]
pub struct GenerateForm {
    pub count: usize,
}

// ── Templates ──

#[derive(Template)]
#[template(path = "invite-codes/list.html")]
struct InviteCodesTemplate<'a> {
    nav_active: &'a str,
    flash: Option<&'a str>,
    codes: Vec<InviteCodeRow>,
    new_codes: Vec<String>,
}

struct InviteCodeRow {
    id: i64,
    code: String,
    status: String,
    used_by: String,
    created_at: String,
}

// ── Handlers ──

pub async fn list(State(state): State<AppState>, _auth: AuthAdmin) -> impl IntoResponse {
    let codes = state.blocking_db(|db| db.list_invite_codes()).await;

    let rows: Vec<InviteCodeRow> = codes
        .iter()
        .map(|c| InviteCodeRow {
            id: c.id,
            code: c.code.clone(),
            status: if c.used_by.is_some() {
                "Used"
            } else {
                "Available"
            }
            .into(),
            used_by: c.used_by.clone().unwrap_or_default(),
            created_at: c.created_at.clone(),
        })
        .collect();

    let tmpl = InviteCodesTemplate {
        nav_active: "Invite Codes",
        flash: None,
        codes: rows,
        new_codes: vec![],
    };
    Html(tmpl.render().unwrap()).into_response()
}

pub async fn generate(
    State(state): State<AppState>,
    _auth: AuthAdmin,
    Form(form): Form<GenerateForm>,
) -> impl IntoResponse {
    let count = form.count.min(1000);
    if count == 0 {
        return Redirect::to("/invite-codes").into_response();
    }

    let new_codes = state
        .blocking_db(move |db| db.create_invite_codes(count, "admin"))
        .await;

    info!("[web] generated {} invite codes", new_codes.len());

    let codes = state.blocking_db(|db| db.list_invite_codes()).await;

    let rows: Vec<InviteCodeRow> = codes
        .iter()
        .map(|c| InviteCodeRow {
            id: c.id,
            code: c.code.clone(),
            status: if c.used_by.is_some() {
                "Used"
            } else {
                "Available"
            }
            .into(),
            used_by: c.used_by.clone().unwrap_or_default(),
            created_at: c.created_at.clone(),
        })
        .collect();

    let tmpl = InviteCodesTemplate {
        nav_active: "Invite Codes",
        flash: Some("Codes generated successfully. Copy them now — they won't be shown again."),
        codes: rows,
        new_codes,
    };
    Html(tmpl.render().unwrap()).into_response()
}

pub async fn delete_code(
    State(state): State<AppState>,
    _auth: AuthAdmin,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    state
        .blocking_db(move |db| db.delete_invite_code(id))
        .await;

    info!("[web] deleted invite code id={}", id);
    Redirect::to("/invite-codes").into_response()
}
