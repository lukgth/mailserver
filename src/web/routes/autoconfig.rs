use axum::{
    extract::State,
    response::IntoResponse,
};

use crate::web::AppState;

/// Escape XML-special characters so a hostname cannot inject XML markup.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Thunderbird autoconfig XML endpoint.
/// Returns ISPDB-style XML so Thunderbird configures IMAP+SMTP correctly.
pub async fn autoconfig(State(state): State<AppState>) -> impl IntoResponse {
    let hostname = xml_escape(&state.hostname);
    let xml = format!(
        r#"<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="{hostname}">
    <displayName>Mail</displayName>
    <displayShortName>Mail</displayShortName>
    <incomingServer type="imap">
      <hostname>{hostname}</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>{{EMAILADDRESS}}</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>{hostname}</hostname>
      <port>465</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>{{EMAILADDRESS}}</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>"#
    );
    (
        [(axum::http::header::CONTENT_TYPE, "application/xml")],
        xml,
    )
        .into_response()
}
