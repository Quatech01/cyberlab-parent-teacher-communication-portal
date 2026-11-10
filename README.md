# Parent-Teacher Communication Portal

A secure full-stack messaging platform for UK schools, demonstrating JWT authentication, role-based access control, and a full DevSecOps security baseline in a Node.js/Express application.

## What This Demonstrates

Modern web applications need more than just a login form. This project shows how to build a production-grade authentication layer — JWT access and refresh tokens, bcrypt password hashing, server-side CSRF validation, and row-level RBAC — and how those controls interact to prevent real attacks: a parent cannot message a teacher they have no relationship with, a stale CSRF token is rejected even if the JWT is valid, and a revoked refresh token cannot mint new sessions.

The school messaging domain is intentionally simple so the security controls are easy to follow without domain noise.

## How It Works

```
backend/           Express API — auth, messaging, announcements
  db/
    schema.sql     Tables: users, messages, announcements, refresh_tokens,
                   csrf_tokens, parent_children, teacher_children, audit_log
    seed.js        Demo data: 1 admin, 3 teachers, 4 parents, 4 children
  middleware/
    auth.js        JWT verification (requireAuth) + CSRF header check (requireCsrf)
    rbac.js        requireRole() guard + canSendMessage() graph query
  routes/
    auth.js        /register, /login, /refresh, /logout, /me
    messages.js    inbox, sent, contacts, /send, /:id/read, /:id (DELETE)
    announcements.js  GET /, POST /, DELETE /:id
frontend/
  index.html       Self-contained SPA — login, register, inbox, compose,
                   announcements; all JS and CSS inline, token stored in memory
tests/
  test.js          28 tests: health, auth flow, RBAC, security headers,
                   input validation, business logic
```

**CSRF protection:** login returns a `csrf_token` alongside the JWT. The frontend stores it in a JS variable and sends it as `X-CSRF-Token` on every state-changing request. The backend looks up the stored token for that user ID and rejects mismatches.

**Messaging RBAC:** the backend walks a small relationship graph. A parent can only message teachers who have a `teacher_children` row for a child the parent is linked to in `parent_children`. Teachers see the mirror image. Admins bypass the check. This query runs on every POST to `/api/messages/send`.

**Refresh token uniqueness:** each refresh token includes a `jti` (JWT ID) claim — a 16-byte random hex string — so tokens generated within the same second remain distinct in the database.

## Quick Start

```bash
# Install backend
cd backend && npm install

# Start the server (opens http://127.0.0.1:3000)
node index.js
```

Open `http://127.0.0.1:3000` and log in with any seed account:

| Username     | Password   | Role    |
|--------------|------------|---------|
| `admin`      | Admin@123  | admin   |
| `mrs.smith`  | Teacher@1  | teacher |
| `p.harris`   | Parent@1   | parent  |

**Run the tool (tests gate the push):**

```bash
cd tests && node --test --test-concurrency=1 test.js
```

## Example Test Output

```
✔ GET /health returns 200 and status ok
✔ registers a new user and returns 201
✔ login returns access_token, refresh_token, csrf_token
✔ login with wrong password returns 401
✔ GET /api/auth/me with valid token returns user profile
✔ refresh token issues new access token
✔ admin can create an announcement
✔ parent is blocked from creating an announcement (403)
✔ parent whose child is NOT taught by this teacher gets 403 on send
✔ POST without CSRF token returns 403
tests 28  pass 28  fail 0
```

## Key Takeaways

- **JWT access + refresh pattern:** short-lived access tokens (15 min) reduce exposure; refresh tokens stored server-side can be revoked immediately on logout or compromise, unlike stateless JWTs alone.
- **CSRF tokens for API-first apps:** the double-submit cookie pattern suits traditional forms; for SPA + API, a server-generated token returned at login and stored in JS memory (never localStorage) achieves the same protection without cookies.
- **RBAC at the data layer:** role guards on routes prevent wrong-role access, but row-level checks (can this user message this specific other user?) must happen in the route handler with parameterized queries — not client-side.
- **Parameterized queries prevent SQL injection:** every DB call uses `db.prepare(...).get/run(values)`, never string concatenation. The SQL injection test in the suite confirms the server accepts the payload safely and returns it verbatim — no crash, no data exposure.
- **jti claim prevents refresh token replay collisions:** deterministic JWTs (same payload = same signature) can cause UNIQUE constraint violations when rotated within the same second; a random `jti` claim makes every token globally unique.

## Further Reading

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [RFC 7519 — JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
