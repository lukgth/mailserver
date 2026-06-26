# Security Review — 2026-06-26

## Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| 🔴 CRITICAL | 0 | — |
| 🟠 HIGH | 2 | Rspamd controller unauthenticated, no CSRF |
| 🟡 MEDIUM | 3 | Postfix cipher level, no rate limit on quarantine, no session expiry |
| 🟢 LOW | 2 | bcrypt cost not documented, no input length on quarantine actions |

---

## Findings

### 🟠 HIGH: Rspamd controller API is unauthenticated

**File:** `docker-compose.prod.yml` (rspamd service)

Rspamd's controller API (port 11334) is exposed on the `internal` Docker network without authentication. Any container on the same network can query, release, or delete quarantined emails.

**Fix:** Add Rspamd controller password:
```bash
docker compose exec rspamd rspamadm configwizard
```
Or set `password` in Rspamd's `/etc/rspamd/local.d/worker-controller.inc`.

---

### 🟠 HIGH: No CSRF protection on forms

**Files:** All POST forms (login, registration, domain/account CRUD, quarantine actions)

No CSRF tokens are validated on any form. An attacker could trick an admin into performing actions via a malicious site.

**Mitigation:** The admin panel uses HTTP Basic Auth (not cookies), so CSRF is partially mitigated — the browser won't automatically send credentials cross-origin. However, quarantine actions and registration forms are still vulnerable.

**Fix:** Add Origin/Referer header validation on POST requests, or add CSRF tokens.

---

### 🟡 MEDIUM: Postfix cipher level is `medium`

**File:** `templates/config/postfix-main.cf.txt:48-49`

```
smtpd_tls_ciphers = medium
smtpd_tls_mandatory_ciphers = medium
```

The `medium` cipher level allows 112-bit ciphers. `high` (128-bit+) is recommended.

**Fix:** Change to `high`:
```bash
docker compose exec mailserver postconf -e "smtpd_tls_ciphers = high" "smtpd_tls_mandatory_ciphers = high"
```

---

### 🟡 MEDIUM: No rate limiting on quarantine API

**File:** `src/web/routes/quarantine.rs`

The quarantine list/detail/action endpoints have no rate limiting. An attacker could flood the Rspamd API via the proxy.

**Fix:** Add nginx rate limiting for `/quarantine*` paths, or add in-memory rate limiting in the handler.

---

### 🟡 MEDIUM: No session expiry for admin auth

**File:** `src/web/auth.rs`

HTTP Basic Auth credentials are cached by the browser indefinitely. No session timeout, no logout mechanism.

**Mitigation:** Runs over HTTPS. Credentials are sent with every request.

**Fix:** Add session-based auth with tokens and configurable expiry.

---

### 🟢 LOW: bcrypt cost not documented

**File:** `src/auth.rs`

bcrypt cost defaults to 12 (configurable via `BCRYPT_COST` env var). Not documented in `.env.example`.

**Fix:** Already added to `.env.example` in a previous commit.

---

### 🟢 LOW: No input length validation on quarantine actions

**File:** `src/web/routes/quarantine.rs`

The `ActionForm` accepts any string for the `action` field. While it's passed directly to Rspamd's API, there's no validation that it's one of `release`, `delete`, or `deny`.

**Fix:** Add validation:
```rust
if !["release", "delete", "deny"].contains(&form.action.as_str()) {
    return Redirect::to("/quarantine").into_response();
}
```

---

## Previously Fixed Issues

| Issue | Status |
|-------|--------|
| Docker socket in mailserver container | ✅ Removed (commented out) |
| CORS headers | ✅ Added (mirror origin) |
| Security headers (HSTS, X-Frame, X-Content) | ✅ Added |
| Webhook URL validation (SSRF) | ✅ HTTPS-only, blocks internal IPs |
| Input length limits on registration | ✅ Added |
| bcrypt cost configurable | ✅ Added |
| Postfix ECDSA cipher support | ✅ Fixed (high cipher level) |
| Let's Encrypt cert auto-renewal | ✅ Added |

## Recommendations

1. **Set Rspamd controller password** — run `rspamadm configwizard` in the rspamd container
2. **Upgrade Postfix ciphers to `high`** — one-line postconf command
3. **Add Origin header check** on POST endpoints for CSRF protection
4. **Add rate limiting** on `/quarantine*` in nginx config
