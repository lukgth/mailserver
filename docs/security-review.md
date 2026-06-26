# Security Review

## Findings

### CRITICAL

1. **Docker socket mounted in container** (`docker-compose.prod.yml:70`)
   - `/var/run/docker.sock` is mounted read-write into the mailserver container
   - Allows container escape: any process in the container can run arbitrary Docker commands on the host
   - **Fix:** Remove the mount unless absolutely needed. If needed, use a restricted Docker API proxy or mount read-only.

2. **No CSRF protection** (all forms)
   - All POST forms (login, registration, domain/account/alias CRUD) lack CSRF tokens
   - An attacker could trick an admin into performing actions via a malicious site
   - **Fix:** Add CSRF tokens to all forms, or use SameSite cookies + Origin header validation

3. **No CORS headers** (all API endpoints)
   - No `Access-Control-Allow-Origin` headers set
   - Browser-based API clients can't distinguish legitimate from malicious origins
   - **Fix:** Set restrictive CORS headers (allow only known origins) or use per-request Origin validation

### HIGH

4. **HTTP Basic Auth for admin panel** (`src/web/auth.rs`)
   - Credentials sent with every request (no session tokens)
   - No logout mechanism (credentials cached by browser)
   - No MFA support beyond what the browser provides
   - **Mitigation:** Runs over HTTPS. **Fix:** Add session-based auth with tokens and expiry

5. **Webhook URL not validated** (`src/web/mod.rs:300`)
   - Webhook URL is fetched from DB and used directly in HTTP requests
   - Could be used for SSRF if an attacker gains DB access or admin privileges
   - **Fix:** Validate webhook URL against an allowlist, or require URL to be a valid HTTPS endpoint

6. **Postgres client panics inside tokio runtime** (`src/db.rs`)
   - Synchronous `postgres` client creates its own tokio runtime internally
   - Panics with "Cannot start a runtime from within a runtime" when used from tokio context
   - Poisons the DB mutex, causing all subsequent requests to fail (DoS)
   - **Fix:** Use `tokio-postgres` (async) instead of sync `postgres`, or ensure all DB access is via `std::thread::spawn`

### MEDIUM

7. **No account lockout on failed login**
   - Brute force is only rate-limited by nginx (5 req/min on /login)
   - No exponential backoff or account lockout after N failures
   - **Fix:** Add account lockout after 5 failed attempts (temporary, e.g. 15 min)

8. **Registration rate limit is global, not per-IP**
   - Nginx rate limit on /register is 5 req/min globally
   - A single user could exhaust the limit for everyone
   - **Fix:** Use `$binary_remote_addr` as the rate limit key (already done for /login)

9. **No input length limits on form fields**
   - Username, display name, and other fields have no server-side max length
   - Could allow storage of very large values
   - **Fix:** Add server-side length validation matching DB column limits

### LOW

10. **bcrypt cost not configurable** (`src/auth.rs`)
    - Uses `DEFAULT_COST` (12) which is reasonable but not adjustable
    - **Fix:** Make cost configurable via env var

11. **No security headers on error pages**
    - Error pages (401, 404, etc.) don't include HSTS or other security headers
    - **Fix:** Add security headers to all responses via middleware

12. **Session cookie not set for admin auth**
    - HTTP Basic Auth doesn't use cookies, so no `HttpOnly`, `Secure`, or `SameSite` flags
    - **Fix:** Migrate to session-based auth with proper cookie flags

## Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| CRITICAL | 3 | Docker socket, CSRF, CORS |
| HIGH | 3 | Basic Auth, Webhook SSRF, Postgres panic |
| MEDIUM | 3 | Account lockout, Rate limiting, Input limits |
| LOW | 3 | bcrypt config, Security headers, Session cookies |

## Quick Wins

1. Remove Docker socket mount from prod compose
2. Add CSRF tokens to forms
3. Add CORS headers to API responses
4. Add server-side input length validation
5. Add security headers middleware
