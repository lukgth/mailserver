# Invite Codes + Registration Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-domain registration URL with a single `/register` page that has a domain dropdown and invite code field. Add an admin panel page to generate, list, and delete invite codes.

**Architecture:** New `invite_codes` table gated by a migration. New admin route `/invite-codes` for CRUD. Registration page changed from `/register/:domain` (domain in URL) to `/register` (domain in dropdown, invite code required). Existing `/register/:domain` kept as redirect for backwards compat.

**Tech Stack:** Rust, Axum, Askama, PostgreSQL, existing `db.rs` patterns.

## Global Constraints

- Rust 2021 edition, Axum 0.7, Askama 0.12
- No new dependencies (use existing `rand`, `hex`, `uuid` crates for code generation)
- Follow existing patterns: `Arc<Mutex<Client>>` sync DB, `#[derive(Template)]` for HTML, `Form<T>` for POST handlers
- Templates extend `layout.html`, use existing CSS classes
- Migration file naming: `021_invite_codes.sql`

---

## File Structure

| Action | File | Purpose |
|--------|------|---------|
| Create | `migrations/021_invite_codes.sql` | Schema for `invite_codes` table |
| Modify | `src/db.rs` | Add `InviteCode` struct, migration entry, DB methods |
| Create | `src/web/routes/invite_codes.rs` | Admin route handlers for invite code CRUD |
| Create | `templates/invite-codes/list.html` | Admin UI for viewing/generating/deleting invite codes |
| Modify | `src/web/routes/mod.rs` | Register invite code routes + update registration routes |
| Modify | `src/web/routes/registration.rs` | Change to `/register` with domain dropdown + invite code |
| Modify | `templates/registration/form.html` | Add domain dropdown + invite code field |
| Modify | `templates/layout.html` | Add "Invite Codes" nav item |

---

### Task 1: Database Migration + Models + Methods

**Files:**
- Create: `migrations/021_invite_codes.sql`
- Modify: `src/db.rs` (add struct, migration entry, 5 methods)

**Interfaces:**
- Produces: `InviteCode` struct, `db.create_invite_codes(count, created_by) -> Vec<String>`, `db.list_invite_codes() -> Vec<InviteCode>`, `db.use_invite_code(code) -> bool`, `db.delete_invite_code(id)`, `db.get_registration_domains() -> Vec<Domain>`

- [ ] **Step 1: Create the migration file**

```sql
-- Invite codes for gated self-registration.
-- Each code is a 16-char hex string. Once used, the code is consumed.
CREATE TABLE IF NOT EXISTS invite_codes (
    id BIGSERIAL PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    used_by TEXT,
    used_at TEXT,
    created_by TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invite_codes_code ON invite_codes(code);
```

- [ ] **Step 2: Add InviteCode struct to `src/db.rs`**

Add after the existing `Domain` struct (around line 80):

```rust
#[derive(Clone, Serialize)]
pub struct InviteCode {
    pub id: i64,
    pub code: String,
    pub used_by: Option<String>,
    pub used_at: Option<String>,
    pub created_by: String,
    pub created_at: String,
}
```

- [ ] **Step 3: Register the migration in `src/db.rs`**

Find the existing `migrations` vec (around line 516) and add the new entry:

```rust
("021_invite_codes".into(), include_str!("../migrations/021_invite_codes.sql").into()),
```

- [ ] **Step 4: Add `get_registration_domains` method to `src/db.rs`**

Add after the existing `get_domain_by_name` method (around line 905):

```rust
    pub fn get_registration_domains(&self) -> Vec<Domain> {
        info!("[db] listing registration-enabled domains");
        let conn = self.conn();
        let rows = conn
            .query(
                "SELECT id, domain, active, dkim_selector, dkim_private_key, dkim_public_key,
                        footer_html, bimi_svg, unsubscribe_enabled, registration_enabled,
                        registration_username_regex
                 FROM domains
                 WHERE active = TRUE AND registration_enabled = TRUE
                 ORDER BY domain",
                &[],
            )
            .unwrap_or_default();
        rows.iter()
            .map(|row| Domain {
                id: row.get(0),
                domain: row.get(1),
                active: row.get(2),
                dkim_selector: row.get(3),
                dkim_private_key: row.get(4),
                dkim_public_key: row.get(5),
                footer_html: row.get(6),
                bimi_svg: row.get(7),
                unsubscribe_enabled: row.get(8),
                registration_enabled: row.get::<_, Option<bool>>(9).unwrap_or(false),
                registration_username_regex: row.get::<_, Option<String>>(10).unwrap_or_default(),
            })
            .collect()
    }
```

- [ ] **Step 5: Add `create_invite_codes` method to `src/db.rs`**

```rust
    pub fn create_invite_codes(&self, count: usize, created_by: &str) -> Vec<String> {
        info!("[db] creating {} invite codes by {}", count, created_by);
        let mut conn = self.conn();
        let ts = now();
        let mut codes = Vec::with_capacity(count);
        for _ in 0..count {
            let code = generate_invite_code();
            if conn
                .execute(
                    "INSERT INTO invite_codes (code, created_by, created_at) VALUES ($1, $2, $3)",
                    &[&code, &created_by, &ts],
                )
                .is_ok()
            {
                codes.push(code);
            }
        }
        info!("[db] created {} invite codes", codes.len());
        codes
    }
```

Add the helper function above the `impl Database` block:

```rust
fn generate_invite_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| format!("{:x}", rng.gen_range(0..16)))
        .collect()
}
```

- [ ] **Step 6: Add `list_invite_codes` method to `src/db.rs`**

```rust
    pub fn list_invite_codes(&self) -> Vec<InviteCode> {
        info!("[db] listing invite codes");
        let conn = self.conn();
        let rows = conn
            .query(
                "SELECT id, code, used_by, used_at, created_by, created_at
                 FROM invite_codes
                 ORDER BY id DESC",
                &[],
            )
            .unwrap_or_default();
        rows.iter()
            .map(|row| InviteCode {
                id: row.get(0),
                code: row.get(1),
                used_by: row.get(2),
                used_at: row.get(3),
                created_by: row.get(4),
                created_at: row.get(5),
            })
            .collect()
    }
```

- [ ] **Step 7: Add `use_invite_code` method to `src/db.rs`**

```rust
    pub fn use_invite_code(&self, code: &str, used_by: &str) -> bool {
        info!("[db] attempting to use invite code: {}", code);
        let mut conn = self.conn();
        let ts = now();
        let result = conn.execute(
            "UPDATE invite_codes SET used_by = $1, used_at = $2
             WHERE code = $3 AND used_by IS NULL",
            &[&used_by, &ts, &code],
        );
        match result {
            Ok(n) => {
                let used = n > 0;
                info!("[db] invite code {} used={}", code, used);
                used
            }
            Err(e) => {
                error!("[db] failed to use invite code {}: {}", code, e);
                false
            }
        }
    }
```

- [ ] **Step 8: Add `delete_invite_code` method to `src/db.rs`**

```rust
    pub fn delete_invite_code(&self, id: i64) {
        info!("[db] deleting invite code id={}", id);
        let mut conn = self.conn();
        if let Err(e) = conn.execute("DELETE FROM invite_codes WHERE id = $1", &[&id]) {
            error!("[db] failed to delete invite code {}: {}", id, e);
        }
    }
```

- [ ] **Step 9: Commit**

```bash
git add migrations/021_invite_codes.sql src/db.rs
git commit -m "feat: add invite_codes table, model, and DB methods"
```

---

### Task 2: Admin Invite Codes Route + Template

**Files:**
- Create: `src/web/routes/invite_codes.rs`
- Create: `templates/invite-codes/list.html`
- Modify: `src/web/routes/mod.rs` (register routes)
- Modify: `templates/layout.html` (nav item)

**Interfaces:**
- Consumes: `InviteCode`, `db.list_invite_codes()`, `db.create_invite_codes()`, `db.delete_invite_code()`
- Produces: Routes `GET /invite-codes`, `POST /invite-codes/generate`, `POST /invite-codes/:id/delete`

- [ ] **Step 1: Create `src/web/routes/invite_codes.rs`**

```rust
use askama::Template;
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect},
    Form,
};
use log::{info, warn};
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

pub async fn list(
    State(state): State<AppState>,
    _auth: AuthAdmin,
) -> impl IntoResponse {
    let codes = state
        .blocking_db(|db| db.list_invite_codes())
        .await;

    let rows: Vec<InviteCodeRow> = codes
        .iter()
        .map(|c| InviteCodeRow {
            id: c.id,
            code: c.code.clone(),
            status: if c.used_by.is_some() { "Used" } else { "Available" }.into(),
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
    let count = form.count.min(1000); // safety cap
    if count == 0 {
        return Redirect::to("/invite-codes").into_response();
    }

    let new_codes = state
        .blocking_db(move |db| db.create_invite_codes(count, "admin"))
        .await;

    info!("[web] generated {} invite codes", new_codes.len());

    let codes = state
        .blocking_db(|db| db.list_invite_codes())
        .await;

    let rows: Vec<InviteCodeRow> = codes
        .iter()
        .map(|c| InviteCodeRow {
            id: c.id,
            code: c.code.clone(),
            status: if c.used_by.is_some() { "Used" } else { "Available" }.into(),
            used_by: c.used_by.clone().unwrap_or_default(),
            created_at: c.created_at.clone(),
        })
        .collect();

    let tmpl = InviteCodesTemplate {
        nav_active: "Invite Codes",
        flash: Some(&format!("Generated {} invite codes", new_codes.len())),
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
```

- [ ] **Step 2: Create `templates/invite-codes/list.html`**

```html
{% extends "layout.html" %}
{% block title %}Invite Codes{% endblock %}
{% block content %}
<h1>Invite Codes</h1>

<h2>Generate Codes</h2>
<form method="post" action="/invite-codes/generate" style="display:flex;gap:0.5rem;align-items:end;margin-bottom:1.5rem">
  <label>Count<br>
    <input type="number" name="count" value="10" min="1" max="1000" required style="width:100px">
  </label>
  <button type="submit">Generate</button>
</form>

{% if !new_codes.is_empty() %}
<h2>Newly Generated</h2>
<p>Copy these codes — they won't be shown again in this format.</p>
<textarea readonly rows="{{ new_codes.len() + 1 }}" style="width:100%;font-family:monospace">{% for c in new_codes %}{{ c }}
{% endfor %}</textarea>
<hr>
{% endif %}

<h2>All Codes ({{ codes.len() }})</h2>
<table>
<thead>
  <tr><th>Code</th><th>Status</th><th>Used By</th><th>Created</th><th></th></tr>
</thead>
<tbody>
{% for c in codes %}
  <tr>
    <td><code>{{ c.code }}</code></td>
    <td>{{ c.status }}</td>
    <td>{{ c.used_by }}</td>
    <td>{{ c.created_at }}</td>
    <td>
      {% if c.status == "Available" %}
      <form method="post" action="/invite-codes/{{ c.id }}/delete" style="display:inline"
            onsubmit="return confirm('Delete this code?')">
        <button type="submit" style="color:var(--color-danger,red)">Delete</button>
      </form>
      {% endif %}
    </td>
  </tr>
{% endfor %}
{% if codes.is_empty() %}
  <tr><td colspan="5"><em>No invite codes yet.</em></td></tr>
{% endif %}
</tbody>
</table>
{% endblock %}
```

- [ ] **Step 3: Register routes in `src/web/routes/mod.rs`**

Add `pub mod invite_codes;` to the module declarations at the top.

Add to the `auth_routes()` function (in the System group, before the closing bracket):

```rust
        .route("/invite-codes", get(invite_codes::list))
        .route("/invite-codes/generate", post(invite_codes::generate))
        .route("/invite-codes/:id/delete", post(invite_codes::delete_code))
```

- [ ] **Step 4: Add nav item to `templates/layout.html`**

Add in the System nav group (before the existing "Replication" link, around line 57):

```html
      <a href="/invite-codes"{% if nav_active == "Invite Codes" %} aria-current="page"{% endif %}>Invite Codes</a>
```

- [ ] **Step 5: Commit**

```bash
git add src/web/routes/invite_codes.rs templates/invite-codes/list.html src/web/routes/mod.rs templates/layout.html
git commit -m "feat: add admin invite codes page with generate/list/delete"
```

---

### Task 3: Update Registration Page with Domain Dropdown + Invite Code

**Files:**
- Modify: `src/web/routes/registration.rs`
- Modify: `templates/registration/form.html`
- Modify: `src/web/routes/mod.rs` (update registration routes)

**Interfaces:**
- Consumes: `db.get_registration_domains()`, `db.use_invite_code()`, `db.get_domain_by_name()`
- Produces: `GET /register` (new), `POST /register` (new), `GET /register/:domain` (redirect to `/register`)

- [ ] **Step 1: Rewrite `src/web/routes/registration.rs`**

Replace the entire file with:

```rust
use askama::Template;
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
        return Err("Username can only contain letters, digits, dots, hyphens, and underscores.".into());
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

/// Redirect /register/:domain to /register (backwards compat)
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
        .map(|d| DomainOption { name: d.domain.clone() })
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
        "[web] POST /register — registration attempt username={}, domain={}",
        form.username, form.domain
    );

    let domain_lower = form.domain.trim().to_ascii_lowercase();

    // Fetch the domain
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

    // Helper to re-render form with error
    let re_render = |error: &str, state: &AppState, dom: &str| {
        let state = state.clone();
        let dom = dom.to_string();
        let error = error.to_string();
        async move {
            let domains = state
                .blocking_db(|db| db.get_registration_domains())
                .await;
            let domain_options: Vec<DomainOption> = domains
                .iter()
                .map(|d| DomainOption { name: d.domain.clone() })
                .collect();
            let tmpl = RegisterFormTemplate {
                nav_active: "",
                flash: None,
                domains: domain_options,
                selected_domain: dom.clone(),
                username: username.clone(),
                username_preview: format!("{}@{}", username, dom),
                name: name.clone(),
                invite_code: invite_code.clone(),
                error: Some(error),
            };
            Html(tmpl.render().unwrap()).into_response()
        }
    };

    // Validate invite code
    if invite_code.is_empty() {
        return re_render("Invite code is required.", &state, &domain_obj.domain).await;
    }

    let code_valid = state
        .blocking_db({
            let code = invite_code.clone();
            let user = format!("{}@{}", username, domain_obj.domain);
            move |db| db.use_invite_code(&code, &user)
        })
        .await;

    if !code_valid {
        return re_render("Invalid or already used invite code.", &state, &domain_obj.domain).await;
    }

    // Validate username
    if let Err(reason) = validate_username(&username, &domain_obj.registration_username_regex) {
        return re_render(&reason, &state, &domain_obj.domain).await;
    }

    // Validate password
    if form.password != form.confirm_password {
        return re_render("Passwords do not match.", &state, &domain_obj.domain).await;
    }
    if form.password.len() < 8 {
        return re_render("Password must be at least 8 characters.", &state, &domain_obj.domain).await;
    }

    // Hash the password
    let hash = match crate::auth::hash_password(&form.password) {
        Ok(h) => h,
        Err(e) => {
            warn!("[register] failed to hash password: {}", e);
            return re_render("Failed to process your registration. Please try again.", &state, &domain_obj.domain).await;
        }
    };

    let domain_name = domain_obj.domain.clone();
    let domain_id = domain_obj.id;

    // Create the account
    let result = state
        .blocking_db(move |db| {
            db.create_account(domain_id, &username, &hash, &name, 0)
        })
        .await;

    match result {
        Ok(_id) => {
            info!(
                "[register] new account created: {}@{}",
                username, domain_name
            );
            fire_webhook(
                &state,
                "account.registered",
                serde_json::json!({
                    "username": username,
                    "domain": domain_name,
                }),
            );
            crate::web::regen_configs(&state).await;

            let tmpl = ErrorTemplate {
                nav_active: "",
                flash: None,
                status_code: 200,
                status_text: "OK",
                title: "Account Created",
                message: &format!(
                    "Your mailbox {}@{} has been created successfully. You can now log in.",
                    username, domain_name
                ),
                back_url: "/",
                back_label: "Home",
            };
            Html(tmpl.render().unwrap()).into_response()
        }
        Err(e) => {
            warn!(
                "[register] failed to create account {}@{}: {}",
                username, domain_name, e
            );
            let reason = if e.contains("23505") || e.to_lowercase().contains("unique") || e.to_lowercase().contains("duplicate") {
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
                    .map(|d| DomainOption { name: d.domain.clone() })
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
```

- [ ] **Step 2: Rewrite `templates/registration/form.html`**

Replace the entire file with:

```html
{% extends "layout.html" %}
{% block title %}Register{% endblock %}
{% block content %}
<h1>Create a Mailbox</h1>
{% if let Some(error) = error %}
<p><strong style="color:var(--color-danger,red)">{{ error }}</strong></p>
{% endif %}
<form method="post" action="/register">
  <label>Domain<br>
    <select name="domain" id="reg_domain" required>
    {% for d in domains %}
      <option value="{{ d.name }}"{% if d.name == selected_domain %} selected{% endif %}>{{ d.name }}</option>
    {% endfor %}
    </select>
  </label>
  <label>Invite Code<br>
    <input type="text" name="invite_code" value="{{ invite_code }}" required
           placeholder="e.g. a1b2c3d4e5f6g7h8" autocomplete="off">
  </label>
  <label>Username (the part before @)<br>
    <input type="text" name="username" id="reg_username" value="{{ username }}" required autocomplete="username"
           placeholder="yourname"
           pattern="[a-zA-Z0-9._-]+" title="Letters, digits, dots, hyphens, and underscores only">
  </label>
  <small>Your email address will be <strong id="reg_preview">{{ username_preview }}</strong></small>
  <label>Display Name (optional)<br>
    <input type="text" name="name" value="{{ name }}" autocomplete="name">
  </label>
  <label>Password<br>
    <input type="password" name="password" required autocomplete="new-password" minlength="8">
  </label>
  <label>Confirm Password<br>
    <input type="password" name="confirm_password" required autocomplete="new-password" minlength="8">
  </label>
  <button type="submit">Create Account</button>
</form>
<script>
(function() {
  var input = document.getElementById('reg_username');
  var preview = document.getElementById('reg_preview');
  var domainSelect = document.getElementById('reg_domain');
  function updatePreview() {
    var u = input.value.trim() || '';
    var d = domainSelect.value || '';
    preview.textContent = u ? u + '@' + d : '@' + d;
  }
  if (input) input.addEventListener('input', updatePreview);
  if (domainSelect) domainSelect.addEventListener('change', updatePreview);
})();
</script>
{% endblock %}
```

- [ ] **Step 3: Update registration routes in `src/web/routes/mod.rs`**

Replace the existing `registration_routes()` function with:

```rust
pub fn registration_routes() -> Router<AppState> {
    Router::new()
        .route("/register", get(registration::show_form).post(registration::handle_form))
        .route("/register/:domain", get(registration::redirect_old))
}
```

- [ ] **Step 4: Commit**

```bash
git add src/web/routes/registration.rs templates/registration/form.html src/web/routes/mod.rs
git commit -m "feat: replace per-domain registration with unified /register page with domain dropdown and invite code"
```

---

### Task 4: Build + Smoke Test

**Files:** None (verification only)

- [ ] **Step 1: Build**

Run: `cargo build --release 2>&1 | tail -20`
Expected: `Finished release target(s)`

- [ ] **Step 2: Verify routes compile and nav renders**

Check the binary starts (if a test DB is available):
```
cargo run -- serve
```
Expected: Server starts on port 8080, `/invite-codes` shows admin page, `/register` shows domain dropdown + invite code form.

- [ ] **Step 3: Commit (if any fixups needed)**

```bash
git add -A
git commit -m "fix: address build issues from invite codes feature"
```

---

## Self-Review

1. **Spec coverage:** ✅ Domain dropdown on registration page, invite code required for registration, admin panel to generate/list/delete invite codes. All covered.
2. **Placeholder scan:** ✅ No TBDs, no "add appropriate error handling", no "similar to Task N". All code is complete.
3. **Type consistency:** ✅ `InviteCode` struct used consistently across DB, route, and template. `DomainOption` used in template matches route code. `RegisterForm` includes all fields used in handler.
