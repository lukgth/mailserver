use serde::Deserialize;

#[derive(Deserialize)]
pub struct DomainForm {
    pub domain: String,
    #[serde(default)]
    pub bimi_svg: String,
    #[serde(default)]
    pub unsubscribe_enabled: Option<String>,
}

#[derive(Deserialize)]
pub struct DomainEditForm {
    pub domain: String,
    #[serde(default)]
    pub active: Option<String>,
    #[serde(default)]
    pub bimi_svg: String,
    #[serde(default)]
    pub unsubscribe_enabled: Option<String>,
    #[serde(default)]
    pub registration_enabled: Option<String>,
    #[serde(default)]
    pub registration_username_regex: String,
}

#[derive(Deserialize)]
pub struct AccountForm {
    pub domain_id: i64,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub quota: Option<i64>,
}

#[derive(Deserialize)]
pub struct AccountEditForm {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub active: Option<String>,
    #[serde(default)]
    pub quota: Option<i64>,
}

#[derive(Deserialize)]
pub struct AliasForm {
    pub source: String,
    pub destination: String,
}

#[derive(Deserialize)]
pub struct AliasEditForm {
    pub source: String,
    pub destination: String,
    #[serde(default)]
    pub active: Option<String>,
}

#[derive(Deserialize)]
pub struct ForwardingForm {
    pub source: String,
    pub destination: String,
    #[serde(default)]
    pub keep_copy: Option<String>,
}

#[derive(Deserialize)]
pub struct ForwardingEditForm {
    pub source: String,
    pub destination: String,
    #[serde(default)]
    pub active: Option<String>,
    #[serde(default)]
    pub keep_copy: Option<String>,
}

#[derive(Deserialize)]
pub struct PasswordForm {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

#[derive(Deserialize)]
pub struct TotpEnableForm {
    pub secret: String,
    pub code: String,
}

#[derive(Deserialize)]
pub struct PixelQuery {
    #[serde(default)]
    pub id: String,
}

#[derive(Deserialize)]
pub struct PixelSettingsForm {
    pub pixel_base_url: String,
}

#[derive(Deserialize)]
pub struct Fail2banSettingForm {
    pub max_attempts: i32,
    pub ban_duration_minutes: i32,
    pub find_time_minutes: i32,
    #[serde(default)]
    pub enabled: Option<String>,
}

#[derive(Deserialize)]
pub struct Fail2banBanForm {
    pub ip_address: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub duration_minutes: Option<i32>,
    #[serde(default)]
    pub permanent: Option<String>,
}

#[derive(Deserialize)]
pub struct Fail2banListForm {
    pub ip_address: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Deserialize)]
pub struct Fail2banGlobalToggleForm {
    #[serde(default)]
    pub enabled: Option<String>,
}

#[derive(Deserialize)]
pub struct SpamblToggleForm {
    pub id: i64,
    #[serde(default)]
    pub enabled: Option<String>,
}

#[derive(Deserialize)]
pub struct UnsubscribeQuery {
    #[serde(default)]
    pub token: String,
}

#[derive(Deserialize)]
pub struct WebhookSettingsForm {
    #[serde(default)]
    pub webhook_url: String,
}

#[derive(Deserialize)]
pub struct FeatureToggleForm {
    #[serde(default)]
    pub milter_enabled: Option<String>,
}

#[derive(Deserialize)]
pub struct MailSettingsForm {
    pub message_size_limit: u64,
    pub daily_send_limit: i64,
    pub default_mailbox_quota: i64,
}

#[derive(Deserialize)]
pub struct RelayForm {
    pub name: String,
    pub host: String,
    #[serde(default)]
    pub port: Option<i32>,
    #[serde(default)]
    pub auth_type: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct RelayEditForm {
    pub name: String,
    pub host: String,
    #[serde(default)]
    pub port: Option<i32>,
    #[serde(default)]
    pub auth_type: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub active: Option<String>,
}

#[derive(Deserialize)]
pub struct RelayAssignmentForm {
    pub assignment_type: String,
    pub pattern: String,
}

#[derive(Deserialize)]
pub struct WebDavSettingsForm {
    #[serde(default)]
    pub webdav_enabled: Option<String>,
    #[serde(default)]
    pub webdav_max_file_size_mb: Option<i64>,
    #[serde(default)]
    pub webdav_quota_mb: Option<i64>,
}

#[derive(Deserialize)]
pub struct TrackingPatternForm {
    pub pattern: String,
}

#[derive(Deserialize)]
pub struct CalDavCalendarForm {
    pub email: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
}

#[derive(Deserialize)]
pub struct CardDavAddressBookForm {
    pub email: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct TrackingRuleForm {
    pub name: String,
    pub match_mode: String,
    pub conditions_json: String,
}

#[derive(Deserialize)]
pub struct RateLimitRuleForm {
    pub name: String,
    pub match_mode: String,
    pub conditions_json: String,
    pub max_messages: i32,
    pub window_seconds: i32,
}

#[derive(Deserialize)]
pub struct FooterContentForm {
    #[serde(default)]
    pub footer_html: String,
}

// ── Admin form validation helpers ────────────────────────────────────────────
//
// Shared length/shape validators for admin-submitted values. All helpers
// reject CR/LF and control characters. They return the normalized value on
// success so callers store the canonical (e.g. lowercased) form.

/// Returns `true` when `s` contains a CR/LF or any control character.
pub fn has_control_chars(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || c == '\r' || c == '\n')
}

/// Domain-name validation: lowercase, ≤253, `[a-z0-9.-]`, no control chars.
pub fn validate_domain_name(domain: &str) -> Result<String, String> {
    let d = domain.trim().to_ascii_lowercase();
    if d.is_empty() {
        return Err("Domain is required.".into());
    }
    if has_control_chars(&d) {
        return Err("Domain contains invalid characters.".into());
    }
    if d.len() > 253 {
        return Err("Domain must be 253 characters or fewer.".into());
    }
    if !d
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
    {
        return Err("Domain may only contain letters, digits, dots, and hyphens.".into());
    }
    Ok(d)
}

/// Username validation: lowercase, ≤64, `[a-z0-9._-]`. Rejects uppercase
/// letters, whitespace and control characters.
pub fn validate_username(username: &str) -> Result<String, String> {
    let u = username.trim().to_ascii_lowercase();
    if u.is_empty() {
        return Err("Username is required.".into());
    }
    if has_control_chars(&u) || u.chars().any(|c| c.is_whitespace() || c.is_uppercase()) {
        return Err("Username may only contain lowercase letters, digits, dots, hyphens, and underscores.".into());
    }
    if u.len() > 64 {
        return Err("Username must be 64 characters or fewer.".into());
    }
    if !u
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err("Username may only contain letters, digits, dots, hyphens, and underscores.".into());
    }
    Ok(u)
}

/// Display-name/relay-name validation: ≤128 characters, no control chars.
pub fn validate_display_name(name: &str) -> Result<String, String> {
    let n = name.trim().to_string();
    if has_control_chars(&n) {
        return Err("Name contains invalid characters.".into());
    }
    if n.len() > 128 {
        return Err("Name must be 128 characters or fewer.".into());
    }
    Ok(n)
}

/// Basic email-or-catchall shape for alias/forwarding addresses: exactly one
/// `@`, non-empty local (or `*` when `allow_catchall`), non-empty domain,
/// ≤254 characters, no control chars.
pub fn validate_mail_address(value: &str, allow_catchall: bool) -> Result<String, String> {
    let v = value.trim().to_string();
    if v.is_empty() {
        return Err("Address is required.".into());
    }
    if has_control_chars(&v) {
        return Err("Address contains invalid characters.".into());
    }
    if v.len() > 254 {
        return Err("Address must be 254 characters or fewer.".into());
    }
    let mut parts = v.split('@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    if parts.next().is_some() || domain.is_empty() {
        return Err("Address must be in the form 'user@domain.com'.".into());
    }
    if allow_catchall && local == "*" {
        return Ok(v);
    }
    if local.is_empty() || has_control_chars(local) || has_control_chars(domain) {
        return Err("Address contains invalid characters.".into());
    }
    if !local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._-+~%".contains(c))
    {
        return Err("Address local part contains invalid characters.".into());
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err("Address domain contains invalid characters.".into());
    }
    Ok(v)
}

/// Outbound relay host validation: ≤253 characters, optional `:port` suffix,
/// bracketed IPv6 literals, no control chars, hostname `[a-z0-9.-]` or an IP.
pub fn validate_relay_host(host: &str) -> Result<String, String> {
    let h = host.trim().to_string();
    if h.is_empty() {
        return Err("Relay host is required.".into());
    }
    if has_control_chars(&h) {
        return Err("Relay host contains invalid characters.".into());
    }
    if h.len() > 253 {
        return Err("Relay host must be 253 characters or fewer.".into());
    }
    let (host_part, port_part) = if h.starts_with('[') {
        // Bracketed IPv6 literal, optionally followed by :port.
        match h.find(']') {
            Some(idx) => {
                let rest = &h[idx + 1..];
                if rest.is_empty() {
                    (&h[..idx + 1], None)
                } else if let Some(p) = rest.strip_prefix(':') {
                    (&h[..idx + 1], Some(p))
                } else {
                    return Err("Relay host has an invalid format.".into());
                }
            }
            None => return Err("Relay host has an invalid format.".into()),
        }
    } else if let Some((hp, pp)) = h.rsplit_once(':') {
        if hp.is_empty() || pp.is_empty() || !pp.chars().all(|c| c.is_ascii_digit()) {
            return Err("Relay host port must be numeric.".into());
        }
        (hp, Some(pp))
    } else {
        (h.as_str(), None)
    };
    if let Some(p) = port_part {
        match p.parse::<u16>() {
            Ok(1..=65535) => {}
            _ => return Err("Relay host port must be between 1 and 65535.".into()),
        }
    }
    if let Some(inner) = host_part.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if inner.parse::<std::net::Ipv6Addr>().is_err() {
            return Err("Relay host IPv6 address is invalid.".into());
        }
    } else if host_part.parse::<std::net::Ipv4Addr>().is_err() {
        if !host_part
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        {
            return Err("Relay host may only contain letters, digits, dots, and hyphens.".into());
        }
    }
    Ok(h)
}
