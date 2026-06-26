use askama::Template;
use axum::{extract::State, response::Html};
use log::debug;

use crate::web::auth::AuthAdmin;
use crate::web::AppState;

#[derive(Template)]
#[template(path = "dns-records/records.html")]
struct DnsRecordsTemplate<'a> {
    nav_active: &'a str,
    flash: Option<&'a str>,
    hostname: &'a str,
    domains: Vec<DnsDomain>,
}

struct DnsDomain {
    name: String,
    mx: String,
    spf: String,
    dkim_selector: String,
    dkim_key: String,
    dmarc: String,
    a_record: String,
}

pub async fn page(auth: AuthAdmin, State(state): State<AppState>) -> Html<String> {
    debug!(
        "[web] GET /dns-records — DNS records page for username={}",
        auth.admin.username
    );

    let domains = state
        .blocking_db(|db| db.list_domains())
        .await;

    let hostname = state.hostname.clone();

    let dns_domains: Vec<DnsDomain> = domains
        .iter()
        .filter(|d| d.active)
        .map(|d| {
            let dkim_key = d.dkim_public_key.clone().unwrap_or_default();
            DnsDomain {
                name: d.domain.clone(),
                mx: format!("mx.{}", d.domain),
                spf: format!("v=spf1 mx a ip4:{} ~all", hostname),
                dkim_selector: d.dkim_selector.clone(),
                dkim_key,
                dmarc: format!("v=DMARC1; p=quarantine; rua=mailto:dmarc@{}; pct=100", d.domain),
                a_record: hostname.clone(),
            }
        })
        .collect();

    let tmpl = DnsRecordsTemplate {
        nav_active: "DNS Records",
        flash: None,
        hostname: &hostname,
        domains: dns_domains,
    };
    Html(tmpl.render().unwrap())
}
