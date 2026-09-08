//! Auto-provisioning: connect to a remote server via SSH, install all mailserver
//! dependencies, upload the current binary and supporting files, and configure
//! the system service — idempotently (already-done steps are skipped).
//!
//! Credentials are only held in memory for the duration of the SSH session and
//! are never written to disk.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use log::{error, info, warn};
use sha2::{Digest, Sha256};
use russh::client;
use russh::client::AuthResult;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg};
use russh::ChannelMsg;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::future::Future;


// ── Result type for remote exec ───────────────────────────────────────────────

/// Result of a remote command: (stdout, stderr, exit_code).
#[derive(Debug, Clone)]
pub(crate) struct CmdResult {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) exit_code: i32,
}

impl CmdResult {
    pub(crate) fn success(&self) -> bool {
        self.exit_code == 0
    }
}
// ── SSH Handler ───────────────────────────────────────────────────────────────

/// russh client handler with host-key verification.
///
/// On connect the server's SHA-256 host key fingerprint is printed. The key is
/// then verified against a known_hosts-style file (default:
/// `/etc/mailserver/known_hosts`, override with `PROVISION_KNOWN_HOSTS`):
/// * a matching entry → accepted;
/// * no entry for the host → accepted **only** if the operator opted in with
///   `--accept-new-host-key` / `PROVISION_ACCEPT_NEW_HOSTS=1`, in which case
///   the key is persisted to the known_hosts file;
/// * a differing entry → hard rejection.
pub(crate) struct SshHandler {
    /// Host name/IP used to look up the entry in the known_hosts file.
    host: String,
    /// SSH port (used for `[host]:port` known_hosts entries).
    port: u16,
    /// Path of the known_hosts-style file to check against / persist to.
    known_hosts: PathBuf,
    /// Accept and persist a previously unknown host key.
    accept_new: bool,
}

impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        // SHA-256 fingerprint over the OpenSSH wire blob of the key
        // (string(algorithm) || string(key data)) — the same digest that
        // `ssh-keygen -lf` prints for a host key.
        let fingerprint = match server_public_key.to_bytes() {
            Ok(wire_bytes) => {
                let digest = Sha256::digest(&wire_bytes);
                BASE64.encode(digest)
            }
            Err(e) => {
                error!(
                    "[provision] cannot serialize server public key for fingerprinting: {}",
                    e
                );
                return Ok(false);
            }
        };

        info!(
            "[provision] remote host key fingerprint: SHA256:{} (algorithm {})",
            fingerprint,
            server_public_key.algorithm()
        );

        match russh::keys::check_known_hosts_path(
            &self.host,
            self.port,
            server_public_key,
            &self.known_hosts,
        ) {
            Ok(true) => {
                info!(
                    "[provision] host key matches known_hosts entry in {}",
                    self.known_hosts.display()
                );
                Ok(true)
            }
            Ok(false) => {
                // No recorded key for this host (or no known_hosts file yet).
                if self.accept_new {
                    match russh::keys::known_hosts::learn_known_hosts_path(
                        &self.host,
                        self.port,
                        server_public_key,
                        &self.known_hosts,
                    ) {
                        Ok(()) => {
                            info!(
                                "[provision] accepted and recorded new host key in {}",
                                self.known_hosts.display()
                            );
                            Ok(true)
                        }
                        Err(e) => {
                            error!(
                                "[provision] cannot persist host key to {}: {}",
                                self.known_hosts.display(),
                                e
                            );
                            Ok(false)
                        }
                    }
                } else {
                    error!(
                        "[provision] REJECTED: no known_hosts entry for {}:{} and the host key was not explicitly accepted.",
                        self.host, self.port
                    );
                    error!(
                        "[provision] compare the fingerprint above (SHA256:{}) against the server's real key, then re-run with --accept-new-host-key (or PROVISION_ACCEPT_NEW_HOSTS=1) to trust it.",
                        fingerprint
                    );
                    Ok(false)
                }
            }
            Err(e) => {
                // A known_hosts entry exists for this host but the key differs.
                error!(
                    "[provision] REJECTED: host key MISMATCH against {}: {}",
                    self.known_hosts.display(),
                    e
                );
                error!(
                    "[provision] got SHA256:{} — remove the stale entry (ssh-keygen -R {}:{}) only if you are sure the server's key legitimately changed.",
                    fingerprint, self.host, self.port
                );
                Ok(false)
            }
        }
    }
}

// ── Shell escaping helpers ────────────────────────────────────────────────────
//
// russh-0.60.2's `Channel::exec(want_reply, command)` only accepts a single
// byte-string command, so we have to escape arguments ourselves. Every
// string interpolated into a remote command MUST go through `sh_single_quote`
// first. Failing to do so allows shell injection (RCE) on the remote.
//
// The implementation embeds the input inside a single-quoted POSIX shell
// string; the only byte that has special meaning inside single quotes is the
// single quote itself, which we close, escape, and re-open around.

/// Quote a string for safe inclusion in a POSIX shell command line.
///
/// The returned value is a single-quoted POSIX string (e.g. `"a'b"` becomes
/// `"'a'\\''b'"`). Always safe to embed unquoted in a remote command.
pub(crate) fn sh_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Execute a remote command from a program + argv vector. Each argument is
/// shell-quoted via `sh_single_quote` before being joined, so user-controlled
/// paths (e.g. `--key`, file paths, script arguments) cannot break out of
/// their position and inject arbitrary shell.
///
/// Note: russh-0.60.2 only exposes `Channel::exec(want_reply, command)` (a
/// single shell string). We compose the string from a `sh_single_quote`'d
/// argv. The remote still runs under a shell, but every argument is
/// pre-quoted so positional `;` / `$()` / `&&` cannot escape.
pub async fn exec_argv(
    session: &mut client::Handle<SshHandler>,
    program: &str,
    args: &[&str],
) -> Result<CmdResult, Box<dyn std::error::Error>> {
    let mut parts: Vec<String> = Vec::with_capacity(args.len() + 1);
    parts.push(sh_single_quote(program));
    for a in args {
        parts.push(sh_single_quote(a));
    }
    let cmd = parts.join(" ");
    exec(session, &cmd).await
}

#[cfg(test)]
mod shell_quote_tests {
    use super::*;

    #[test]
    fn quotes_plain_ascii() {
        assert_eq!(sh_single_quote("a"), "'a'");
        assert_eq!(sh_single_quote("/tmp/path"), "'/tmp/path'");
    }

    #[test]
    fn escapes_single_quote() {
        assert_eq!(sh_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn escapes_injection_attempts() {
        // The injection attempt is now inside a single-quoted string; the
        // remote shell cannot interpret it.
        assert_eq!(sh_single_quote("; rm -rf /"), "'; rm -rf /'");
        assert_eq!(sh_single_quote("$(id)"), "'$(id)'");
        assert_eq!(sh_single_quote("`id`"), "'`id`'");
    }

    #[test]
    fn preserves_backslashes() {
        // Backslashes have no special meaning inside single quotes; they are
        // passed through unchanged.  This is the desired POSIX behaviour.
        assert_eq!(sh_single_quote(r"C:\Users\alice"), r"'C:\Users\alice'");
    }

    #[test]
    fn empty_string_is_a_valid_argument() {
        assert_eq!(sh_single_quote(""), "''");
    }
}

// ── Param Parsing ─────────────────────────────────────────────────────────────

struct Params {
    host: String,
    port: u16,
    user: String,
    key_path: Option<PathBuf>,
    password: Option<String>,
    /// Optional path to a env-file that will be uploaded to /etc/mailserver/env
    env_file: Option<PathBuf>,
    /// Path of the known_hosts-style file used for host-key verification.
    /// Defaults to `/etc/mailserver/known_hosts`; override with
    /// `PROVISION_KNOWN_HOSTS`.
    known_hosts: PathBuf,
    /// Accept and persist a host key that has no known_hosts entry
    /// (`--accept-new-host-key` or `PROVISION_ACCEPT_NEW_HOSTS=1`).
    accept_new_host_key: bool,
}

fn parse_args(args: &[String]) -> Result<Params, String> {
    let mut host = None;
    let mut port: u16 = 22;
    let mut user = None;
    let mut key_path = None;
    let mut password = None;
    let mut env_file = None;
    let mut accept_new_host_key = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                i += 1;
                host = Some(args.get(i).ok_or("--host requires a value")?.clone());
            }
            "--port" => {
                i += 1;
                port = args
                    .get(i)
                    .ok_or("--port requires a value")?
                    .parse::<u16>()
                    .map_err(|_| "--port must be a valid port number (1-65535)")?;
            }
            "--user" | "--username" => {
                i += 1;
                user = Some(args.get(i).ok_or("--user requires a value")?.clone());
            }
            "--key" => {
                i += 1;
                let v = args.get(i).ok_or("--key requires a path")?;
                key_path = Some(PathBuf::from(v));
            }
            "--password" => {
                i += 1;
                warn!("[provision] --password is visible in the process list; prefer PROVISION_SSH_PASSWORD or the interactive prompt");
                password = Some(args.get(i).ok_or("--password requires a value")?.clone());
            }
            "--env-file" => {
                i += 1;
                let v = args.get(i).ok_or("--env-file requires a path")?;
                env_file = Some(PathBuf::from(v));
            }
            "--accept-new-host-key" => {
                accept_new_host_key = true;
            }
            other => {
                return Err(format!("unknown argument: {}", other));
            }
        }
        i += 1;
    }

    Ok(Params {
        host: host.ok_or("--host is required")?,
        port,
        user: user.ok_or("--user is required")?,
        key_path,
        password,
        env_file,
        known_hosts: PathBuf::from("/etc/mailserver/known_hosts"),
        accept_new_host_key,
    })
}

/// Prompt for the SSH password on stdin.
///
/// The input is echoed (no termios no-echo manipulation is performed); for
/// unattended or higher-security runs use `PROVISION_SSH_PASSWORD` instead.
/// Returns `None` on EOF or empty input, in which case authentication proceeds
/// with the key only.
fn prompt_password() -> Option<String> {
    eprint!("[provision] SSH password (may be a key passphrase): ");
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => {
            let pwd = line.trim_end_matches(['\r', '\n']).to_string();
            if pwd.is_empty() {
                None
            } else {
                Some(pwd)
            }
        }
    }
}

// ── Entry Point ───────────────────────────────────────────────────────────────

/// Run the `provision` command.  `args` is the slice of CLI arguments that
/// follow the `provision` subcommand token.
pub async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut params = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("provision: {}", e);
            eprintln!();
            print_usage();
            std::process::exit(1);
        }
    };

    // Environment-driven overrides for host-key policy.
    if std::env::var("PROVISION_ACCEPT_NEW_HOSTS").as_deref() == Ok("1") {
        params.accept_new_host_key = true;
    }
    if let Ok(path) = std::env::var("PROVISION_KNOWN_HOSTS") {
        if !path.is_empty() {
            params.known_hosts = PathBuf::from(path);
        }
    }

    // Password preference: CLI flag (discouraged) > PROVISION_SSH_PASSWORD >
    // stdin prompt.
    if params.password.is_none() {
        if let Ok(pwd) = std::env::var("PROVISION_SSH_PASSWORD") {
            if !pwd.is_empty() {
                params.password = Some(pwd);
                info!("[provision] using PROVISION_SSH_PASSWORD for authentication");
            }
        }
    }
    if params.password.is_none() {
        params.password = prompt_password();
    }

    info!(
        "[provision] connecting to {}:{} as user '{}'",
        params.host, params.port, params.user
    );

    let mut session = connect_ssh(&params).await?;

    info!("[provision] SSH session established. Starting provisioning sequence.");
    info!("[provision] ─── step 1/8: detect package manager ───");
    let pkg_mgr = detect_pkg_manager(&mut session).await?;
    info!("[provision] package manager: {}", pkg_mgr);

    info!("[provision] ─── step 2/8: install system dependencies ───");
    install_deps(&mut session, &pkg_mgr).await?;

    info!("[provision] ─── step 3/8: create users and directories ───");
    setup_users_and_dirs(&mut session, &pkg_mgr).await?;

    info!("[provision] ─── step 4/8: upload mailserver binary ───");
    upload_binary(&mut session).await?;

    info!("[provision] ─── step 5/8: upload supporting files ───");
    upload_support_files(&mut session).await?;

    if let Some(ref ef) = params.env_file {
        info!("[provision] uploading env file: {:?}", ef);
        upload_file(
            &mut session,
            ef.to_str()
                .ok_or("env file path contains invalid UTF-8")?,
            "/etc/mailserver/env",
            false,
            true,
        )
        .await?;
        info!("[provision] env file uploaded to /etc/mailserver/env");
    } else {
        info!("[provision] --env-file not specified; skipping env file upload");
        info!("[provision] hint: create /etc/mailserver/env on the remote with DATABASE_URL etc.");
    }

    info!("[provision] ─── step 6/8: initial mailserver setup ───");
    initial_setup(&mut session).await?;

    info!("[provision] ─── step 7/8: configure system service ───");
    setup_service(&mut session, &pkg_mgr).await?;

    info!("[provision] ─── step 8/8: enable and start service ───");
    start_service(&mut session, &pkg_mgr).await?;

    info!("[provision] ─────────────────────────────────────────────");
    info!("[provision] provisioning complete!");

    session
        .disconnect(russh::Disconnect::ByApplication, "done", "English")
        .await?;

    Ok(())
}

// ── SSH Connection ────────────────────────────────────────────────────────────

async fn connect_ssh(
    params: &Params,
) -> Result<client::Handle<SshHandler>, Box<dyn std::error::Error>> {
    let config = Arc::new(client::Config::default());
    let addr = (params.host.as_str(), params.port);

    let mut session = client::connect(
        config,
        addr,
        SshHandler {
            host: params.host.clone(),
            port: params.port,
            known_hosts: params.known_hosts.clone(),
            accept_new: params.accept_new_host_key,
        },
    )
    .await?;

    // Try public-key authentication first
    let mut authed = false;
    if let Some(ref key_path) = params.key_path {
        info!("[provision] attempting public-key authentication with {:?}", key_path);
        match load_key(key_path, params.password.as_deref()) {
            Ok(key) => {
                let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), None);
                match session.authenticate_publickey(&params.user, key_with_alg).await {
                    Ok(AuthResult::Success) => {
                        info!("[provision] public-key authentication succeeded");
                        authed = true;
                    }
                    Ok(AuthResult::Failure { .. }) => {
                        warn!("[provision] public-key authentication rejected by server");
                    }
                    Err(e) => {
                        warn!("[provision] public-key authentication error: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("[provision] failed to load private key {:?}: {}", key_path, e);
            }
        }
    }

    // Fall back to password authentication
    if !authed {
        if let Some(ref pwd) = params.password {
            info!("[provision] attempting password authentication");
            match session.authenticate_password(&params.user, pwd).await {
                Ok(AuthResult::Success) => {
                    info!("[provision] password authentication succeeded");
                    authed = true;
                }
                Ok(AuthResult::Failure { .. }) => {
                    warn!("[provision] password authentication rejected by server");
                }
                Err(e) => {
                    return Err(format!("password authentication error: {}", e).into());
                }
            }
        }
    }

    if !authed {
        return Err("all authentication methods failed; check --key / --password".into());
    }

    Ok(session)
}

/// Load a private key from disk, trying without a passphrase first and then
/// with the supplied password as passphrase.
fn load_key(path: &Path, password: Option<&str>) -> Result<PrivateKey, Box<dyn std::error::Error>> {
    // Try passphrase-protected first if a password was given
    if let Some(pwd) = password {
        if let Ok(kp) = russh::keys::load_secret_key(path, Some(pwd)) {
            return Ok(kp);
        }
    }
    // Try unencrypted key
    let kp = russh::keys::load_secret_key(path, None)?;
    Ok(kp)

}

/// Maximum number of bytes captured per stream (stdout / stderr) before the
/// capture is truncated with a marker. Remote commands are trusted-ish but may
/// legitimately produce huge output (e.g. a verbose `apt-get`); unbounded
/// capture would let a misbehaving remote exhaust local memory.
const MAX_CAPTURE: usize = 1024 * 1024;
const TRUNC_MARKER: &str = "\n...[truncated: output exceeds 1 MiB]";

/// Append `data` to `target`, capping `target` at `MAX_CAPTURE` bytes; when
/// the cap is hit a truncation marker is appended once.
fn push_capped(target: &mut String, data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let remaining = MAX_CAPTURE.saturating_sub(target.len());
    if remaining == 0 {
        // Marker was already appended when the cap was hit; drop further data.
        return;
    }
    if text.len() <= remaining {
        target.push_str(&text);
    } else {
        // `floor_char_boundary` keeps the cut at a UTF-8 boundary so we never
        // truncate mid-character.
        let end = text.floor_char_boundary(remaining);
        target.push_str(&text[..end]);
        target.push_str(TRUNC_MARKER);
    }
}

/// Execute a single command on the remote host and collect stdout/stderr.
async fn exec(
    session: &mut client::Handle<SshHandler>,
    cmd: &str,
) -> Result<CmdResult, Box<dyn std::error::Error>> {
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, cmd).await?;

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code: i32 = -1;

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                push_capped(&mut stdout, &data);
            }
            Some(ChannelMsg::ExtendedData { data, .. }) => {
                push_capped(&mut stderr, &data);
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                exit_code = exit_status as i32;
            }
            None => break,
            _ => {}
        }
    }

    Ok(CmdResult {
        stdout,
        stderr,
        exit_code,
    })
}

#[cfg(test)]
mod capture_limit_tests {
    use super::*;

    #[test]
    fn keeps_output_under_cap_with_marker() {
        let mut target = String::new();
        push_capped(&mut target, &[b'a'; MAX_CAPTURE]);
        assert_eq!(target.len(), MAX_CAPTURE);

        // Further data is dropped; the marker is added only once (on the push
        // that crossed the cap), so the capture never grows unbounded.
        push_capped(&mut target, &[b'b'; 4096]);
        assert_eq!(target.len(), MAX_CAPTURE);
    }

    #[test]
    fn appends_marker_when_data_crosses_cap() {
        let mut target = String::new();
        // 3 bytes over the cap.
        push_capped(&mut target, &[b'a'; MAX_CAPTURE + 3]);
        assert!(target.ends_with(TRUNC_MARKER));
        assert_eq!(target.len(), MAX_CAPTURE + TRUNC_MARKER.len());
        // Marker still present (not duplicated) after more data.
        push_capped(&mut target, b"more");
        assert!(target.ends_with(TRUNC_MARKER));
    }

    #[test]
    fn never_truncates_mid_utf8_character() {
        let mut target = String::new();
        // "é" is 2 bytes; the cap cut must land on a char boundary.
        push_capped(&mut target, "é".repeat(MAX_CAPTURE / 2 + 1).as_bytes());
        assert!(std::str::from_utf8(target.as_bytes()).is_ok());
        assert!(target.ends_with(TRUNC_MARKER));
    }

    #[test]
    fn small_output_is_untouched() {
        let mut target = String::new();
        push_capped(&mut target, b"hello");
        assert_eq!(target, "hello");
    }
}

/// Execute a command, log stdout/stderr, and return an error on non-zero exit
/// so a failed step aborts the whole provisioning run.
async fn run_remote(
    session: &mut client::Handle<SshHandler>,
    description: &str,
    cmd: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("[provision] $ {}", cmd);
    let res = exec(session, cmd).await?;

    let out = res.stdout.trim().to_string();
    let err = res.stderr.trim().to_string();

    if !out.is_empty() {
        for line in out.lines() {
            info!("[provision]   {}", line);
        }
    }
    if !err.is_empty() {
        for line in err.lines() {
            warn!("[provision]   stderr: {}", line);
        }
    }

    if res.success() {
        info!("[provision] ✓ {}", description);
        Ok(())
    } else {
        error!(
            "[provision] ✗ {} (exit code {}) — aborting provisioning",
            description, res.exit_code
        );
        Err(format!(
            "remote command failed (exit {}): {}",
            res.exit_code, description
        )
        .into())
    }
}

/// Check whether a remote file or directory exists.
async fn remote_exists(
    session: &mut client::Handle<SshHandler>,
    path: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let res = exec_argv(session, "test", &["-e", path]).await?;
    Ok(res.success())
}

/// Check whether a remote command is available in PATH.
async fn command_exists(
    session: &mut client::Handle<SshHandler>,
    command: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    // `command` is the only attacker-controlled piece; quoting it via
    // `sh_single_quote` neutralises `;` / `$(...)` / `&&`. `command -v` tests
    // for the program in PATH without executing it. The `command -v` and the
    // redirect are appended unquoted because they are static literals.
    let cmd = format!(
        "command -v {} >/dev/null 2>&1",
        sh_single_quote(command),
    );
    let res = exec(session, &cmd).await?;
    Ok(res.success())
}

// ── File Upload ───────────────────────────────────────────────────────────────

/// Validate that a remote path consists only of characters safe to embed in a
/// shell command. The path will be passed through `sh_single_quote` before
/// being interpolated into a remote `exec` call, but defence-in-depth: we
/// reject any path containing characters outside this allowlist so a bug in
/// the quoting layer cannot yield RCE on the remote.
///
/// Allowed characters: ASCII letters, digits, dot, underscore, slash, plus,
/// hyphen. This matches the path grammar used by every legitimate remote
/// path in this binary (e.g. `/etc/mailserver/env`, `/usr/local/bin/foo.sh`,
/// `/app/templates/config/x.txt`).
fn validate_remote_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("remote path is empty".to_string());
    }
    if !path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'+' | b'-'))
    {
        return Err(format!(
            "remote path {:?} contains characters outside the safe allowlist (A-Za-z0-9._/+-)",
            path
        ));
    }
    if path.contains("..") {
        return Err(format!("remote path {:?} contains a '..' segment", path));
    }
    Ok(())
}

#[cfg(test)]
mod remote_path_tests {
    use super::validate_remote_path;

    #[test]
    fn accepts_normal_paths() {
        assert!(validate_remote_path("/etc/mailserver/env").is_ok());
        assert!(validate_remote_path("/usr/local/bin/mailserver").is_ok());
        assert!(validate_remote_path("/app/templates/config/postfix-main.cf.txt").is_ok());
        assert!(validate_remote_path("/data/dkim/example.com.private").is_ok());
    }

    #[test]
    fn rejects_injection_attempts() {
        assert!(validate_remote_path("'; touch /tmp/pwn #").is_err());
        assert!(validate_remote_path("/etc/$(id)/file").is_err());
        assert!(validate_remote_path("/etc/`id`/file").is_err());
        assert!(validate_remote_path("/etc/foo|bar").is_err());
        assert!(validate_remote_path("/etc/foo;rm").is_err());
        assert!(validate_remote_path("/etc/foo&bar").is_err());
        assert!(validate_remote_path("").is_err());
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_remote_path("/etc/../shadow").is_err());
        assert!(validate_remote_path("../etc/passwd").is_err());
    }
}

/// Upload a local file to the remote host via the SSH exec channel.
/// The file is base64-encoded on the local side and decoded on the remote side,
/// so no out-of-band protocol (SCP/SFTP) is required.
///
/// For large files (> 60 KB) the content is split into multiple `dd` append
/// blocks to stay within shell argument length limits.
///
/// The upload is atomic: content is written to a temporary sibling path
/// (`<remote_path>.mailserver-new`), its size is verified with `stat`, the
/// final mode is applied, and only then is it moved into place — a reader
/// never observes a partial file at the final path. Uploaded files are
/// chmod'd deterministically (755 for executables, 644 otherwise).
///
/// * `skip_if_exists` — when `true` the upload is skipped if the remote file
///   already exists.
async fn upload_file(
    session: &mut client::Handle<SshHandler>,
    local_path: &str,
    remote_path: &str,
    executable: bool,
    skip_if_exists: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_remote_path(remote_path)?;

    if skip_if_exists && remote_exists(session, remote_path).await? {
        info!("[provision] skip upload (already exists): {}", remote_path);
        return Ok(());
    }

    info!("[provision] uploading {} → {}", local_path, remote_path);
    let data = std::fs::read(local_path)
        .map_err(|e| format!("cannot read local file {}: {}", local_path, e))?;

    // Atomic: write to a temporary sibling, then rename into place.
    let temp_path = format!("{}.mailserver-new", remote_path);
    validate_remote_path(&temp_path)?;

    // Ensure parent directory exists
    if let Some(parent) = Path::new(remote_path).parent() {
        let parent_str = parent.to_string_lossy();
        if !parent_str.is_empty() && parent_str != "/" {
            validate_remote_path(&parent_str)?;
            exec_argv(session, "mkdir", &["-p", &parent_str]).await?;
        }
    }

    // Split into 48 KiB chunks (base64 of 48 KiB ≈ 65 KiB, well within Linux
    // ARG_MAX and most SSH server limits).
    const CHUNK: usize = 48 * 1024;
    let total = data.len();
    let chunks: Vec<&[u8]> = data.chunks(CHUNK).collect();
    let n = chunks.len();

    info!("[provision] file size: {} bytes, {} chunk(s)", total, n);

    // Truncate (or create) the temp file first. This also discards any stale
    // temp file left by an interrupted previous run.
    // Use `:` (POSIX no-op) and redirect to a quoted path — the safest
    // portable way to truncate to zero bytes.
    let trunc_cmd = format!(": > {}", sh_single_quote(&temp_path));
    exec(session, &trunc_cmd).await?;

    for (idx, chunk) in chunks.iter().enumerate() {
        let encoded = BASE64.encode(chunk);
        // Quote both `encoded` (base64 alphabet, but we still quote it for
        // uniformity) and `temp_path` via `sh_single_quote`. The
        // `validate_remote_path` check above ensures the latter is safe even
        // before quoting.
        let cmd = format!(
            "printf '%s' {} | base64 -d >> {}",
            sh_single_quote(&encoded),
            sh_single_quote(&temp_path),
        );
        let res = exec(session, &cmd).await?;
        if !res.success() {
            return Err(format!(
                "upload chunk {}/{} to {} failed (exit {})",
                idx + 1,
                n,
                remote_path,
                res.exit_code
            )
            .into());
        }
    }

    // Verify the transferred size before exposing the file at its final path.
    let stat_res = exec_argv(session, "stat", &["-c", "%s", temp_path.as_str()]).await?;
    if !stat_res.success() {
        return Err(format!(
            "cannot stat uploaded temp file {} (exit {})",
            temp_path, stat_res.exit_code
        )
        .into());
    }
    let remote_size: usize = stat_res
        .stdout
        .trim()
        .parse()
        .map_err(|_| format!("cannot parse remote size from {:?}", stat_res.stdout))?;
    if remote_size != total {
        return Err(format!(
            "upload size mismatch for {}: remote {} bytes, local {} bytes",
            remote_path, remote_size, total
        )
        .into());
    }

    // Apply the final mode to the temp file, then move it into place so the
    // destination atomically gains the correct content AND permissions.
    let mode = if executable { "755" } else { "644" };
    let chmod_res = exec_argv(session, "chmod", &[mode, temp_path.as_str()]).await?;
    if !chmod_res.success() {
        return Err(format!(
            "cannot chmod {} (exit {})",
            temp_path, chmod_res.exit_code
        )
        .into());
    }
    let mv_res = exec_argv(session, "mv", &["-f", temp_path.as_str(), remote_path]).await?;
    if !mv_res.success() {
        return Err(format!(
            "cannot move {} into place (exit {})",
            remote_path, mv_res.exit_code
        )
        .into());
    }

    info!("[provision] ✓ uploaded {}", remote_path);
    Ok(())
}

/// Upload all `*.txt` template files under a local directory tree to the
/// remote, preserving relative paths under `remote_base`.
async fn upload_dir(
    session: &mut client::Handle<SshHandler>,
    local_dir: &str,
    remote_base: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_remote_path(remote_base)?;
    let local_path = Path::new(local_dir);
    if !local_path.exists() {
        info!("[provision] local directory {} does not exist, skipping", local_dir);
        return Ok(());
    }

    exec_argv(session, "mkdir", &["-p", remote_base]).await?;

    upload_dir_recursive(session, local_path, local_path, remote_base).await
}

fn upload_dir_recursive<'a>(
    session: &'a mut client::Handle<SshHandler>,
    base: &'a Path,
    current: &'a Path,
    remote_base: &'a str,
) -> std::pin::Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>> + 'a>>
{
    Box::pin(async move {
        for entry in std::fs::read_dir(current)
            .map_err(|e| format!("cannot read directory {:?}: {}", current, e))?
        {
            let entry = entry?;
            let path = entry.path();
            let rel = path.strip_prefix(base).unwrap();
            let remote_path = format!("{}/{}", remote_base, rel.to_string_lossy());
            // `remote_path` is constructed from the validated `remote_base`
            // plus a relative file name from the local tree. Both segments
            // should pass `validate_remote_path`; the check is a guardrail
            // against a future caller passing an unvalidated `remote_base`.
            validate_remote_path(&remote_path)?;

            if path.is_dir() {
                exec_argv(session, "mkdir", &["-p", &remote_path]).await?;
                upload_dir_recursive(session, base, &path, remote_base).await?;
            } else {
                // Skip if already present
                if !remote_exists(session, &remote_path).await? {
                    upload_file(
                        session,
                        path.to_str().ok_or_else(|| {
                            format!("file path contains invalid UTF-8: {:?}", path)
                        })?,
                        &remote_path,
                        false,
                        false,
                    )
                    .await?;
                } else {
                    info!("[provision] skip upload (already exists): {}", remote_path);
                }
            }
        }
        Ok(())
    })
}
// ── Provisioning Steps ────────────────────────────────────────────────────────

/// Detect which package manager is available on the remote host.
async fn detect_pkg_manager(
    session: &mut client::Handle<SshHandler>,
) -> Result<String, Box<dyn std::error::Error>> {
    for pm in &["apt-get", "apk", "dnf", "yum"] {
        if command_exists(session, pm).await? {
            return Ok(pm.to_string());
        }
    }
    Err("no supported package manager found (tried apt-get, apk, dnf, yum)".into())
}

/// Install all required system packages, skipping those that are already present.
async fn install_deps(
    session: &mut client::Handle<SshHandler>,
    pkg_mgr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Binaries that must be present after installation
    struct Dep {
        binary: &'static str,    // `command -v <binary>` check
        apt_pkg: &'static str,
        apk_pkg: &'static str,
        yum_pkg: &'static str,
    }

    let deps = [
        Dep { binary: "postfix",    apt_pkg: "postfix",          apk_pkg: "postfix",          yum_pkg: "postfix" },
        Dep { binary: "dovecot",    apt_pkg: "dovecot-core",     apk_pkg: "dovecot",          yum_pkg: "dovecot" },
        Dep { binary: "opendkim",   apt_pkg: "opendkim",         apk_pkg: "opendkim",         yum_pkg: "opendkim" },
        Dep { binary: "openssl",    apt_pkg: "openssl",          apk_pkg: "openssl",          yum_pkg: "openssl" },
        Dep { binary: "curl",       apt_pkg: "curl",             apk_pkg: "curl",             yum_pkg: "curl" },
        Dep { binary: "psql",       apt_pkg: "postgresql-client",apk_pkg: "postgresql-client",yum_pkg: "postgresql" },
    ];

    // Update package index once (only for apt/apk)
    match pkg_mgr {
        "apt-get" => {
            run_remote(session, "apt-get update", "DEBIAN_FRONTEND=noninteractive apt-get update -qq").await?;
        }
        "apk" => {
            run_remote(session, "apk update", "apk update -q").await?;
        }
        _ => {}
    }

    for dep in &deps {
        if command_exists(session, dep.binary).await? {
            info!("[provision] skip: {} already installed", dep.binary);
            continue;
        }

        let pkg = match pkg_mgr {
            "apt-get" => dep.apt_pkg,
            "apk" => dep.apk_pkg,
            _ => dep.yum_pkg,
        };

        let install_cmd = match pkg_mgr {
            "apt-get" => format!("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {}", pkg),
            "apk" => format!("apk add --quiet {}", pkg),
            "dnf" => format!("dnf install -y -q {}", pkg),
            _ => format!("yum install -y -q {}", pkg),
        };

        // `run_remote` fails fast: a non-zero install exit aborts provisioning.
        run_remote(session, &format!("install {}", pkg), &install_cmd).await?;
    }

    // Extra dovecot sub-packages for LMTP
    let lmtp_check = match pkg_mgr {
        "apk" => "test -f /usr/lib/dovecot/lmtp",
        "apt-get" => "dpkg -l dovecot-lmtpd 2>/dev/null | grep -q '^ii'",
        _ => "test -f /usr/libexec/dovecot/lmtp",
    };

    if !exec(session, lmtp_check).await?.success() {
        let lmtp_pkg = match pkg_mgr {
            "apt-get" => "dovecot-lmtpd dovecot-imapd dovecot-pop3d",
            "apk" => "dovecot-lmtpd dovecot-pigeonhole-plugin",
            _ => "dovecot",
        };
        let install_cmd = match pkg_mgr {
            "apt-get" => format!("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {}", lmtp_pkg),
            "apk" => format!("apk add --quiet {}", lmtp_pkg),
            "dnf" => format!("dnf install -y -q {}", lmtp_pkg),
            _ => format!("yum install -y -q {}", lmtp_pkg),
        };
        run_remote(session, "install dovecot LMTP/IMAP/POP3 plugins", &install_cmd).await?;
    } else {
        info!("[provision] skip: dovecot LMTP already installed");
    }

    Ok(())
}

/// Create the vmail and opendkim system users and all required directories.
async fn setup_users_and_dirs(
    session: &mut client::Handle<SshHandler>,
    pkg_mgr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // User creation helpers differ between distros
    let (addgroup_flags, adduser_flags) = match pkg_mgr {
        "apk" => ("-S", "-S -D -H -s /sbin/nologin"),
        _ => ("--system", "--system --no-create-home --shell /usr/sbin/nologin"),
    };

    for (user, group) in &[("vmail", "vmail"), ("opendkim", "opendkim")] {
        // `user` and `group` are hardcoded literals, but quote them via
        // sh_single_quote for symmetry and to prevent any future refactor
        // from quietly introducing a runtime-controlled value.
        let id_cmd = format!(
            "{} >/dev/null 2>&1",
            sh_single_quote(&format!("id {}", user)),
        );
        let exists = exec(session, &id_cmd).await?.success();
        if exists {
            info!("[provision] skip: user {} already exists", user);
        } else {
            // Create group then user. addgroup_flags is a static literal so
            // it is safe to splice directly; user/group are quoted. There is
            // deliberately no trailing `|| true`: with fail-fast provisioning
            // a group/user that could not be created must abort, not silently
            // continue with a half-broken system.
            let group_cmd = format!(
                "groupadd {} {} 2>/dev/null || addgroup {} {}",
                addgroup_flags,
                sh_single_quote(group),
                addgroup_flags,
                sh_single_quote(group),
            );
            let group_res = exec(session, &group_cmd).await?;
            if !group_res.success() {
                return Err(format!("failed to create system group {}", group).into());
            }
            let user_cmd = format!(
                "useradd {} -g {} {} 2>/dev/null || adduser {} -G {} {}",
                adduser_flags,
                sh_single_quote(group),
                sh_single_quote(user),
                adduser_flags,
                sh_single_quote(group),
                sh_single_quote(user),
            );
            run_remote(
                session,
                &format!("create system user {}", user),
                &user_cmd,
            )
            .await?;
        }
    }

    // Required directories
    let dirs = [
        "/data/ssl",
        "/data/dkim",
        "/data/mail",
        "/data/db",
        "/var/spool/postfix",
        "/app/templates/config",
        "/app/migrations",
        "/app/static",
        "/etc/mailserver",
        "/usr/local/bin",
    ];

    for dir in &dirs {
        if remote_exists(session, dir).await? {
            info!("[provision] skip: directory {} already exists", dir);
        } else {
            run_remote(session, &format!("create directory {}", dir), &format!("mkdir -p {}", dir)).await?;
        }
    }

    // Ownership
    run_remote(session, "chown /data/mail → vmail", "chown -R vmail:vmail /data/mail").await?;
    run_remote(session, "chown /data/dkim → opendkim", "chown -R opendkim:opendkim /data/dkim").await?;

    Ok(())
}

/// Upload the currently-running mailserver binary to the remote host.
async fn upload_binary(
    session: &mut client::Handle<SshHandler>,
) -> Result<(), Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot determine current executable path: {}", e))?;
    let exe_str = exe
        .to_str()
        .ok_or("current executable path contains invalid UTF-8")?;

    info!("[provision] current binary: {}", exe_str);

    // Always overwrite the binary so the remote gets the current version.
    // (skip_if_exists = false)
    upload_file(session, exe_str, "/usr/local/bin/mailserver", true, false).await?;

    Ok(())
}

/// Upload `templates/`, `migrations/`, `static/`, and `entrypoint.sh` to the
/// remote host.  Each file is skipped if it already exists.
async fn upload_support_files(
    session: &mut client::Handle<SshHandler>,
) -> Result<(), Box<dyn std::error::Error>> {
    // entrypoint.sh
    if Path::new("entrypoint.sh").exists() {
        upload_file(session, "entrypoint.sh", "/entrypoint.sh", true, true).await?;
    } else if Path::new("/app/entrypoint.sh").exists() {
        upload_file(session, "/app/entrypoint.sh", "/entrypoint.sh", true, true).await?;
    } else {
        info!("[provision] entrypoint.sh not found locally, skipping");
    }

    // Template config files
    for local_dir in &["templates/config", "/app/templates/config"] {
        if Path::new(local_dir).exists() {
            upload_dir(session, local_dir, "/app/templates/config").await?;
            break;
        }
    }

    // Migrations
    for local_dir in &["migrations", "/app/migrations"] {
        if Path::new(local_dir).exists() {
            upload_dir(session, local_dir, "/app/migrations").await?;
            break;
        }
    }

    // Static assets
    for local_dir in &["static", "/app/static"] {
        if Path::new(local_dir).exists() {
            upload_dir(session, local_dir, "/app/static").await?;
            break;
        }
    }

    Ok(())
}

/// Run initial one-time setup commands on the remote host.  Each command is
/// guarded by a quick existence check so it is skipped if already done.
async fn initial_setup(
    session: &mut client::Handle<SshHandler>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Source the env file if present; otherwise warn and continue
    let env_prefix = "set -a && [ -f /etc/mailserver/env ] && . /etc/mailserver/env; set +a;";

    // TLS certificates
    if remote_exists(session, "/data/ssl/cert.pem").await?
        && remote_exists(session, "/data/ssl/key.pem").await?
    {
        info!("[provision] skip: TLS certificates already exist");
    } else {
        run_remote(
            session,
            "generate TLS certificates",
            &format!("{} /usr/local/bin/mailserver gencerts", env_prefix),
        )
        .await?;
    }

    // Database seed (idempotent — mailserver seed is safe to re-run)
    run_remote(
        session,
        "seed admin user",
        &format!("{} /usr/local/bin/mailserver seed", env_prefix),
    )
    .await?;

    // Generate mail service configs
    run_remote(
        session,
        "generate mail configs",
        &format!("{} /usr/local/bin/mailserver genconfig", env_prefix),
    )
    .await?;

    Ok(())
}

/// Write and enable the system service definition (systemd or OpenRC).
async fn setup_service(
    session: &mut client::Handle<SshHandler>,
    _pkg_mgr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Detect init system
    let has_systemd = command_exists(session, "systemctl").await?;
    let has_openrc = command_exists(session, "rc-update").await?;

    if has_systemd {
        if remote_exists(session, "/etc/systemd/system/mailserver.service").await? {
            info!("[provision] skip: systemd unit already installed");
        } else {
            let unit = SYSTEMD_UNIT;
            write_remote_text(session, "/etc/systemd/system/mailserver.service", unit).await?;
            run_remote(session, "reload systemd daemon", "systemctl daemon-reload").await?;
            info!("[provision] systemd unit installed");
        }
    } else if has_openrc {
        if remote_exists(session, "/etc/init.d/mailserver").await? {
            info!("[provision] skip: OpenRC init script already installed");
        } else {
            // Use apk-style openrc init script
            write_remote_text(session, "/etc/init.d/mailserver", OPENRC_INIT).await?;
            run_remote(session, "chmod openrc init script", "chmod +x /etc/init.d/mailserver").await?;
            info!("[provision] OpenRC init script installed");
        }
    } else {
        warn!("[provision] neither systemd nor OpenRC detected; manual service configuration required");
    }

    Ok(())
}

/// Enable and start (or restart) the mailserver service.
async fn start_service(
    session: &mut client::Handle<SshHandler>,
    _pkg_mgr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let has_systemd = command_exists(session, "systemctl").await?;
    let has_openrc = command_exists(session, "rc-update").await?;

    if has_systemd {
        run_remote(session, "enable mailserver service", "systemctl enable mailserver").await?;
        run_remote(session, "restart mailserver service", "systemctl restart mailserver").await?;
        // Status check is diagnostic, not a provisioning step: it must not
        // abort the run, but the outcome is logged explicitly (the restart
        // itself already failed fast on a non-zero exit above).
        let status = exec(session, "systemctl is-active mailserver").await?;
        let state = status.stdout.trim().to_string();
        if status.success() {
            info!("[provision] mailserver service is active ({})", state);
        } else {
            warn!(
                "[provision] mailserver service not reported active: {} (exit {})",
                if state.is_empty() { "unknown state" } else { &state },
                status.exit_code
            );
        }
    } else if has_openrc {
        // `rc-update add` exits non-zero when the service is already in the
        // runlevel (a plain re-provision), so check first instead of masking
        // the failure with `|| true`.
        let already_added = exec(
            session,
            "rc-update show default 2>/dev/null | grep -qw mailserver",
        )
        .await?
        .success();
        if already_added {
            info!("[provision] skip: mailserver already in default runlevel");
        } else {
            run_remote(session, "add to default runlevel", "rc-update add mailserver default").await?;
        }
        run_remote(session, "start mailserver service", "rc-service mailserver restart").await?;
    } else {
        warn!("[provision] cannot start service automatically; start /entrypoint.sh manually");
    }

    Ok(())
}

// ── Text File Upload Helper ───────────────────────────────────────────────────

/// Write a UTF-8 string to a remote file using an exec channel.
async fn write_remote_text(
    session: &mut client::Handle<SshHandler>,
    remote_path: &str,
    content: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Defence-in-depth: even though the only callers pass hardcoded paths,
    // we validate to prevent a future caller from injecting a path that
    // could break out of its single-quoted form on the remote.
    validate_remote_path(remote_path)?;

    // Ensure parent directory exists
    if let Some(parent) = Path::new(remote_path).parent() {
        let p = parent.to_string_lossy();
        if !p.is_empty() && p != "/" {
            validate_remote_path(&p)?;
            exec_argv(session, "mkdir", &["-p", &p]).await?;
        }
    }

    let encoded = BASE64.encode(content.as_bytes());
    // Both `encoded` (base64 alphabet) and `remote_path` (allowlisted) are
    // wrapped in `sh_single_quote` for uniformity — the validator above
    // ensures the path is in the safe set even if the quoting were ever
    // bypassed.
    let cmd = format!(
        "printf '%s' {} | base64 -d > {}",
        sh_single_quote(&encoded),
        sh_single_quote(remote_path),
    );
    let res = exec(session, &cmd).await?;
    if !res.success() {
        return Err(format!("failed to write {}: exit {}", remote_path, res.exit_code).into());
    }
    info!("[provision] ✓ wrote {}", remote_path);
    Ok(())
}

// ── Service Unit Definitions ──────────────────────────────────────────────────

const SYSTEMD_UNIT: &str = r#"[Unit]
Description=Mailserver (Postfix + Dovecot + OpenDKIM managed by mailserver binary)
After=network.target
Wants=network.target

[Service]
Type=simple
EnvironmentFile=-/etc/mailserver/env
ExecStart=/entrypoint.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"#;

const OPENRC_INIT: &str = r#"#!/sbin/openrc-run

name="mailserver"
description="Mailserver (Postfix + Dovecot + OpenDKIM)"
command="/entrypoint.sh"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"

depend() {
    need net
}
"#;

// ── Usage ─────────────────────────────────────────────────────────────────────

pub fn print_usage() {
    println!("Usage:");
    println!("  mailserver provision --host <host> --user <user> [options]");
    println!();
    println!("Options:");
    println!("  --host <host>         Remote host name or IP address (required)");
    println!("  --port <port>         SSH port (default: 22)");
    println!("  --user <user>         SSH login username (required)");
    println!("  --key <path>          Path to SSH private key file (recommended)");
    println!("  --password <pwd>      Password for SSH auth or encrypted key passphrase");
    println!("                        (discouraged: visible in the process list; use");
    println!("                        PROVISION_SSH_PASSWORD or the interactive prompt)");
    println!("  --env-file <path>     Local .env file to upload as /etc/mailserver/env");
    println!("  --accept-new-host-key Accept and persist a host key with no matching");
    println!("                        known_hosts entry (first connect) after comparing");
    println!("                        the printed SHA-256 fingerprint");
    println!();
    println!("Environment variables:");
    println!("  PROVISION_SSH_PASSWORD          SSH password (preferred over --password)");
    println!("  PROVISION_KNOWN_HOSTS           known_hosts file for host-key checks");
    println!("                                  (default: /etc/mailserver/known_hosts)");
    println!("  PROVISION_ACCEPT_NEW_HOSTS=1    Accept and persist an unknown host key");
    println!();
    println!("The command connects via SSH, installs system dependencies, uploads the");
    println!("current mailserver binary and supporting files, configures the system");
    println!("service, and starts it. Steps that are already done are automatically");
    println!("skipped, and provisioning aborts on the first failed step. Credentials");
    println!("are only kept in memory and never written to disk.");
    println!();
    println!("Host keys: the server key fingerprint (SHA256:...) is printed on every");
    println!("connect and verified against PROVISION_KNOWN_HOSTS. A mismatch aborts;");
    println!("an unknown key requires --accept-new-host-key / PROVISION_ACCEPT_NEW_HOSTS=1");
    println!("before it is recorded and trusted.");
    println!();
    println!("Examples:");
    println!("  mailserver provision --host mail.example.com --user root --key ~/.ssh/id_ed25519");
    println!("  mailserver provision --host 10.0.0.5 --user admin --key ~/.ssh/id_rsa --password mypass");
    println!("  mailserver provision --host mail.example.com --user root --password s3cr3t --env-file .env.prod");
}
