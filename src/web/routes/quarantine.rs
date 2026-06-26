use askama::Template;
use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
};

use crate::web::auth::AuthAdmin;
use crate::web::AppState;

#[derive(Template)]
#[template(path = "quarantine/list.html")]
struct QuarantineStatusTemplate<'a> {
    nav_active: &'a str,
    flash: Option<&'a str>,
}

pub async fn list(
    _auth: AuthAdmin,
    State(_state): State<AppState>,
) -> Response {
    debug!("[web] GET /quarantine — spam filter status");
    let tmpl = QuarantineStatusTemplate {
        nav_active: "Quarantine",
        flash: None,
    };
    Html(tmpl.render().unwrap()).into_response()
}
