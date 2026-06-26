use axum::{
    extract::State,
    response::IntoResponse,
};

use crate::web::AppState;

/// Thunderbird autoconfig XML endpoint.
/// Returns ISPDB-style XML so Thunderbird configures IMAP+SMTP correctly.
pub async fn autoconfig(State(state): State<AppState>) -> impl IntoResponse {
    let hostname = &state.hostname;
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
      <port>587</port>
      <socketType>STARTTLS</socketType>
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
