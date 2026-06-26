use askama::Template;
use axum::http::StatusCode;
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use log::{info, warn};
use serde::Deserialize;

use crate::web::fire_webhook;
use crate::web::AppState;

// ── Forms ──

#[derive(Deserialize)]
pub struct RegisterForm {
    pub domain: String,
    pub username: String,
    pub name: String,
    pub password: String,
    pub confirm_password: String,
    pub invite_code: String,
}

// ── Templates ──

#[derive(Template)]
#[template(path = "registration/form.html")]
struct RegisterFormTemplate<'a> {
    nav_active: &'a str,
    flash: Option<&'a str>,
    domains: Vec<DomainOption>,
    selected_domain: String,
    username: String,
    username_preview: String,
    name: String,
    invite_code: String,
    error: Option<String>,
}

struct DomainOption {
    name: String,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate<'a> {
    nav_active: &'a str,
    flash: Option<&'a str>,
    status_code: u16,
    status_text: &'a str,
    title: &'a str,
    message: &'a str,
    back_url: &'a str,
    back_label: &'a str,
}

#[derive(Template)]
#[template(path = "registration/success.html")]
struct SuccessTemplate<'a> {
    nav_active: &'a str,
    flash: Option<&'a str>,
    email: String,
    hostname: &'a str,
}

// ── Helpers ──

fn validate_username(username: &str, regex_pattern: &str) -> Result<(), String> {
    if username.is_empty() {
        return Err("Username is required.".into());
    }
    if username.len() < 3 || username.len() > 64 {
        return Err("Username must be between 3 and 64 characters.".into());
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(
            "Username may only contain letters, digits, dots, hyphens, and underscores.".into(),
        );
    }
    if regex_pattern.is_empty() {
        return Ok(());
    }
    match regex::Regex::new(regex_pattern) {
        Ok(re) => {
            if !re.is_match(username) {
                return Err("Username does not meet the requirements for this domain.".into());
            }
        }
        Err(_) => {
            warn!(
                "[register] domain has invalid username regex '{}', ignoring",
                regex_pattern
            );
        }
    }
    Ok(())
}

// ── Handlers ──

/// Redirect old /register/:domain to /register (backwards compat)
pub async fn redirect_old(Path(_domain): Path<String>) -> Redirect {
    Redirect::to("/register")
}

/// Show the public registration form with domain dropdown + invite code.
pub async fn show_form(State(state): State<AppState>) -> Response {
    info!("[web] GET /register — registration form");

    let domains = state
        .blocking_db(|db| db.get_registration_domains())
        .await;

    if domains.is_empty() {
        let tmpl = ErrorTemplate {
            nav_active: "",
            flash: None,
            status_code: 404,
            status_text: "Not Found",
            title: "Registration Unavailable",
            message: "Registration is not currently available for any domain.",
            back_url: "/",
            back_label: "Home",
        };
        return Html(tmpl.render().unwrap()).into_response();
    }

    let domain_options: Vec<DomainOption> = domains
        .iter()
        .map(|d| DomainOption {
            name: d.domain.clone(),
        })
        .collect();

    let default_domain = domain_options[0].name.clone();

    let tmpl = RegisterFormTemplate {
        nav_active: "",
        flash: None,
        domains: domain_options,
        selected_domain: default_domain.clone(),
        username: String::new(),
        username_preview: format!("@{}", default_domain),
        name: String::new(),
        invite_code: String::new(),
        error: None,
    };
    Html(tmpl.render().unwrap()).into_response()
}

/// Handle the registration form submission.
pub async fn handle_form(
    State(state): State<AppState>,
    Form(form): Form<RegisterForm>,
) -> Response {
    info!(
        "[web] POST /register — attempt username={}, domain={}",
        form.username, form.domain
    );

    let domain_lower = form.domain.trim().to_ascii_lowercase();

    let domain_record = state
        .blocking_db(move |db| db.get_domain_by_name(&domain_lower))
        .await;

    let domain_obj = match domain_record {
        Some(d) if d.active && d.registration_enabled => d,
        _ => {
            let tmpl = ErrorTemplate {
                nav_active: "",
                flash: None,
                status_code: 404,
                status_text: "Not Found",
                title: "Registration Unavailable",
                message: "Registration is not available for this domain.",
                back_url: "/register",
                back_label: "Try Again",
            };
            return Html(tmpl.render().unwrap()).into_response();
        }
    };

    let username = form.username.trim().to_ascii_lowercase();
    let name = form.name.trim().to_string();
    let invite_code = form.invite_code.trim().to_string();
    let password = form.password.clone();
    let confirm_password = form.confirm_password.clone();

    // Helper to re-render form with error
    let re_render = {
        let state = state.clone();
        let username = username.clone();
        let name = name.clone();
        let invite_code = invite_code.clone();
        let domain_name = domain_obj.domain.clone();
        move |error: &str| {
            let state = state.clone();
            let error = error.to_string();
            let username = username.clone();
            let name = name.clone();
            let invite_code = invite_code.clone();
            let domain_name = domain_name.clone();
            async move {
                let domains = state
                    .blocking_db(|db| db.get_registration_domains())
                    .await;
                let domain_options: Vec<DomainOption> = domains
                    .iter()
                    .map(|d| DomainOption {
                        name: d.domain.clone(),
                    })
                    .collect();
                let tmpl = RegisterFormTemplate {
                    nav_active: "",
                    flash: None,
                    domains: domain_options,
                    selected_domain: domain_name.clone(),
                    username,
                    username_preview: format!("user@{}", domain_name),
                    name,
                    invite_code,
                    error: Some(error),
                };
                (StatusCode::UNPROCESSABLE_ENTITY, Html(tmpl.render().unwrap())).into_response()
            }
        }
    };

    // Validate invite code
    if invite_code.is_empty() {
        return re_render("Invite code is required.").await;
    }

    let code_valid = state
        .blocking_db({
            let code = invite_code.clone();
            let user = format!("{}@{}", username, domain_obj.domain);
            move |db| db.use_invite_code(&code, &user)
        })
        .await;

    if !code_valid {
        return re_render("Invalid or already used invite code.")
            .await;
    }

    // Validate username
    if let Err(reason) = validate_username(&username, &domain_obj.registration_username_regex) {
        return re_render(&reason).await;
    }

    // Validate display name length
    if name.len() > 128 {
        return re_render("Display name must be 128 characters or fewer.").await;
    }

    // Validate invite code format (32 hex chars)
    if invite_code.len() != 32 || !invite_code.chars().all(|c| c.is_ascii_hexdigit()) {
        return re_render("Invalid invite code.").await;
    }

    // Validate password
    if password != confirm_password {
        return re_render("Passwords do not match.").await;
    }
    if password.len() < 8 {
        return re_render("Password must be at least 8 characters.")
            .await;
    }

    // Hash the password
    let hash = match crate::auth::hash_password(&password) {
        Ok(h) => h,
        Err(e) => {
            warn!("[register] failed to hash password: {}", e);
            return re_render("Failed to process your registration. Please try again.")
                .await;
        }
    };

    let domain_name = domain_obj.domain.clone();
    let domain_id = domain_obj.id;
    let username_clone = username.clone();
    let name_clone = name.clone();

    let result = state
        .blocking_db(move |db| db.create_account(domain_id, &username_clone, &hash, &name_clone, 0))
        .await;

    match result {
        Ok(_id) => {
            info!(
                "[register] new account created: {}@{}",
                username, domain_name
            );
            // Fire webhook and regenerate configs on background thread
            // (avoids postgres runtime conflict — db access must not happen in tokio context)
            let db = state.db.clone();
            let hostname = state.hostname.clone();
            let webhook_user = username.clone();
            let webhook_domain = domain_name.clone();
            std::thread::spawn(move || {
                // Fire webhook from this thread (no tokio runtime)
                fire_webhook_with_db(&db, "account.registered", serde_json::json!({
                    "username": webhook_user,
                    "domain": webhook_domain,
                }));
                // Regenerate configs via subprocess
                let output = std::process::Command::new("/usr/local/bin/mailserver")
                    .arg("genconfig")
                    .env("HOSTNAME", &hostname)
                    .output();
                match output {
                    Ok(o) if o.status.success() => {
                        info!("[register] genconfig subprocess completed");
                    }
                    Ok(o) => {
                        let stderr = String::from_utf8_lossy(&o.stderr);
                        warn!("[register] genconfig subprocess failed: {}", stderr);
                    }
                    Err(e) => {
                        warn!("[register] failed to spawn genconfig: {}", e);
                    }
                }
            });

            // Redirect to success page (no database access needed)
            let email = format!("{}@{}", username, domain_name);
            let encoded_email = email.replace('@', "%40");
            Redirect::to(&format!("/register/success?email={}", encoded_email)).into_response()
        }
        Err(e) => {
            warn!(
                "[register] failed to create account {}@{}: {}",
                username, domain_name, e
            );
            let reason = if e.contains("23505")
                || e.to_lowercase().contains("unique")
                || e.to_lowercase().contains("duplicate")
            {
                "That username is already taken on this domain.".to_string()
            } else {
                "Registration failed. Please try again.".to_string()
            };
            let tmpl = RegisterFormTemplate {
                nav_active: "",
                flash: None,
                domains: state
                    .blocking_db(|db| db.get_registration_domains())
                    .await
                    .iter()
                    .map(|d| DomainOption {
                        name: d.domain.clone(),
                    })
                    .collect(),
                selected_domain: domain_name.clone(),
                username: username.clone(),
                username_preview: format!("{}@{}", username, domain_name),
                name,
                invite_code: String::new(),
                error: Some(reason),
            };
            Html(tmpl.render().unwrap()).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct SuccessQuery {
    pub email: String,
}

/// Show the registration success page with connection info.
/// No database access — safe to render in tokio context.
pub async fn show_success(
    State(state): State<AppState>,
    query: axum::extract::Query<SuccessQuery>,
) -> impl IntoResponse {
    let tmpl = SuccessTemplate {
        nav_active: "",
        flash: None,
        email: query.email.clone(),
        hostname: &state.hostname,
    };
    Html(tmpl.render().unwrap())
}
