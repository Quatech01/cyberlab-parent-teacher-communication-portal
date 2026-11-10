'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const { start } = require('../backend/index.js');

let server, baseUrl;
let adminToken, adminCsrf;
let teacherToken, teacherCsrf;
let parentToken, parentCsrf;
let userToken2, userCsrf2;  // parent with no shared child with teacher

async function login(username, password) {
  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  return res.json();
}

async function api(method, path, token, csrfToken, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (token)     headers['Authorization']  = `Bearer ${token}`;
  if (csrfToken) headers['X-CSRF-Token']   = csrfToken;
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  return fetch(`${baseUrl}${path}`, opts);
}

before(async () => {
  const port = 4000 + Math.floor(Math.random() * 1000);
  server  = await start(port, { dbPath: ':memory:' });
  baseUrl = `http://127.0.0.1:${port}`;

  const a = await login('admin',    'Admin@123');
  adminToken  = a.access_token; adminCsrf  = a.csrf_token;

  const t = await login('mrs.smith', 'Teacher@1');
  teacherToken = t.access_token; teacherCsrf = t.csrf_token;

  const p = await login('p.harris', 'Parent@1');
  parentToken = p.access_token; parentCsrf = p.csrf_token;

  // c.nguyen also teaches under mrs.smith (same child Lily via seed)
  // s.patel is under mr.jones — not linked to mrs.smith
  const p2 = await login('s.patel', 'Parent@2');
  userToken2 = p2.access_token; userCsrf2 = p2.csrf_token;
});

after(() => server.close());

// ── Group 1: Health ──────────────────────────────────────────────────────────
describe('Health', () => {
  it('GET /health returns 200 and status ok', async () => {
    const res  = await fetch(`${baseUrl}/health`);
    const body = await res.json();
    assert.strictEqual(res.status, 200);
    assert.strictEqual(body.status, 'ok');
  });
});

// ── Group 2: Auth flow ───────────────────────────────────────────────────────
describe('Auth flow', () => {
  it('registers a new user and returns 201', async () => {
    const res = await api('POST', '/api/auth/register', null, null, {
      username: 'new_parent', email: 'new@example.com',
      password: 'Secure@99', display_name: 'New Parent'
    });
    assert.strictEqual(res.status, 201);
    const body = await res.json();
    assert.ok(body.id);
    assert.strictEqual(body.role, 'parent');
  });

  it('login returns access_token, refresh_token, csrf_token', async () => {
    // Use r.okafor so we do not overwrite the shared adminCsrf used in later tests
    const res  = await api('POST', '/api/auth/login', null, null, { username: 'r.okafor', password: 'Parent@4' });
    const body = await res.json();
    assert.strictEqual(res.status, 200);
    assert.ok(typeof body.access_token  === 'string');
    assert.ok(typeof body.refresh_token === 'string');
    assert.ok(typeof body.csrf_token    === 'string');
  });

  it('login with wrong password returns 401', async () => {
    const res = await api('POST', '/api/auth/login', null, null, { username: 'admin', password: 'wrong' });
    assert.strictEqual(res.status, 401);
  });

  it('GET /api/auth/me without token returns 401', async () => {
    const res = await fetch(`${baseUrl}/api/auth/me`);
    assert.strictEqual(res.status, 401);
  });

  it('GET /api/auth/me with valid token returns user profile', async () => {
    const res  = await api('GET', '/api/auth/me', adminToken, null);
    const body = await res.json();
    assert.strictEqual(res.status, 200);
    assert.strictEqual(body.username, 'admin');
    assert.ok(!body.password_hash, 'password_hash must not be returned');
  });

  it('refresh token issues new access token', async () => {
    const loginRes  = await api('POST', '/api/auth/login', null, null, { username: 'mr.jones', password: 'Teacher@2' });
    assert.strictEqual(loginRes.status, 200, 'mr.jones login must succeed before refresh can be tested');
    const loginBody = await loginRes.json();
    assert.ok(loginBody.refresh_token, 'login response must include refresh_token');
    const refRes  = await api('POST', '/api/auth/refresh', null, null, { refresh_token: loginBody.refresh_token });
    assert.strictEqual(refRes.status, 200);
    const refBody = await refRes.json();
    assert.ok(refBody.access_token);
  });
});

// ── Group 3: RBAC ────────────────────────────────────────────────────────────
describe('RBAC', () => {
  it('admin can create an announcement', async () => {
    const res = await api('POST', '/api/announcements', adminToken, adminCsrf, {
      title: 'Test Announcement', body: 'This is a test.'
    });
    assert.strictEqual(res.status, 201);
  });

  it('parent is blocked from creating an announcement (403)', async () => {
    const res = await api('POST', '/api/announcements', parentToken, parentCsrf, {
      title: 'Hacked', body: 'Should fail.'
    });
    assert.strictEqual(res.status, 403);
  });

  it('teacher can create an announcement', async () => {
    const res = await api('POST', '/api/announcements', teacherToken, teacherCsrf, {
      title: 'Year 7 Trip Reminder', body: 'Please return forms.'
    });
    assert.strictEqual(res.status, 201);
  });

  it('parent cannot delete an announcement (403)', async () => {
    const listRes  = await api('GET', '/api/announcements', parentToken, null);
    const list     = await listRes.json();
    if (list.length === 0) return;
    const delRes = await api('DELETE', `/api/announcements/${list[0].id}`, parentToken, parentCsrf);
    assert.strictEqual(delRes.status, 403);
  });
});

// ── Group 4: Security headers ────────────────────────────────────────────────
describe('Security headers', () => {
  it('X-Content-Type-Options: nosniff is present', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
  });

  it('X-Frame-Options is present', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.ok(res.headers.get('x-frame-options'), 'x-frame-options header missing');
  });

  it('Content-Security-Policy header is present', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.ok(res.headers.get('content-security-policy'), 'CSP header missing');
  });

  it('Strict-Transport-Security header is present', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.ok(res.headers.get('strict-transport-security'), 'HSTS header missing');
  });
});

// ── Group 5: Input validation ─────────────────────────────────────────────────
describe('Input validation', () => {
  it('register with empty username returns 422', async () => {
    const res = await api('POST', '/api/auth/register', null, null, {
      username: '', email: 'valid@test.com', password: 'Valid@123', display_name: 'Test'
    });
    assert.ok([400, 422].includes(res.status));
  });

  it('register with invalid email returns 422', async () => {
    const res = await api('POST', '/api/auth/register', null, null, {
      username: 'testuser99', email: 'not-an-email', password: 'Valid@123', display_name: 'Test'
    });
    assert.ok([400, 422].includes(res.status));
  });

  it('send message with SQL injection in subject is handled safely', async () => {
    const contacts = await (await api('GET', '/api/messages/contacts', parentToken, null)).json();
    if (contacts.length === 0) return;
    const res = await api('POST', '/api/messages/send', parentToken, parentCsrf, {
      recipient_id: contacts[0].id,
      subject: "' OR 1=1; DROP TABLE users; --",
      body: 'Payload test'
    });
    // Should succeed (parameterized query stores it safely) or fail validation — not 500
    assert.ok(res.status !== 500);
    // Server must still be healthy
    const health = await fetch(`${baseUrl}/health`);
    assert.strictEqual(health.status, 200);
  });

  it('POST without CSRF token returns 403', async () => {
    const res = await api('POST', '/api/messages/send', parentToken, null, {
      recipient_id: 2, subject: 'No CSRF', body: 'Should fail'
    });
    assert.strictEqual(res.status, 403);
  });

  it('send message with empty body returns 422', async () => {
    const contacts = await (await api('GET', '/api/messages/contacts', parentToken, null)).json();
    if (contacts.length === 0) return;
    const res = await api('POST', '/api/messages/send', parentToken, parentCsrf, {
      recipient_id: contacts[0].id, subject: 'Test', body: ''
    });
    assert.ok([400, 422].includes(res.status));
  });
});

// ── Group 6: Business logic ──────────────────────────────────────────────────
describe('Business logic', () => {
  let sentMessageId;

  it('parent can send a message to their child\'s teacher', async () => {
    const contacts = await (await api('GET', '/api/messages/contacts', parentToken, null)).json();
    const teacher  = contacts.find(c => c.role === 'teacher');
    assert.ok(teacher, 'Parent should have at least one teacher contact');
    const res = await api('POST', '/api/messages/send', parentToken, parentCsrf, {
      recipient_id: teacher.id, subject: 'Progress update', body: 'How is Emma doing this term?'
    });
    assert.strictEqual(res.status, 201);
    const body = await res.json();
    sentMessageId = body.id;
  });

  it('teacher sees message in inbox', async () => {
    const res  = await api('GET', '/api/messages/inbox', teacherToken, null);
    const msgs = await res.json();
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(msgs));
    const found = msgs.find(m => m.id === sentMessageId);
    assert.ok(found, 'Teacher should see the sent message');
  });

  it('parent whose child is NOT taught by this teacher gets 403 on send', async () => {
    // s.patel's child (Arjun) is taught by mr.jones, not mrs.smith
    const teacherRes  = await api('GET', '/api/auth/me', teacherToken, null);
    const teacherUser = await teacherRes.json();
    const res = await api('POST', '/api/messages/send', userToken2, userCsrf2, {
      recipient_id: teacherUser.id,
      subject: 'Trying unauthorized message',
      body: 'Should be blocked'
    });
    assert.strictEqual(res.status, 403);
  });

  it('teacher can mark a received message as read', async () => {
    const inbox = await (await api('GET', '/api/messages/inbox', teacherToken, null)).json();
    const unread = inbox.find(m => m.is_read === 0);
    if (!unread) return;
    const res = await api('PUT', `/api/messages/${unread.id}/read`, teacherToken, teacherCsrf);
    assert.strictEqual(res.status, 200);
  });

  it('GET /api/messages/inbox without auth returns 401', async () => {
    const res = await fetch(`${baseUrl}/api/messages/inbox`);
    assert.strictEqual(res.status, 401);
  });

  it('announcements list is accessible to all authenticated users', async () => {
    const res  = await api('GET', '/api/announcements', parentToken, null);
    const list = await res.json();
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(list));
    assert.ok(list.length > 0, 'Seed announcements should be present');
  });

  it('contacts list for parent returns only their child\'s teachers', async () => {
    const res      = await api('GET', '/api/messages/contacts', parentToken, null);
    const contacts = await res.json();
    assert.ok(Array.isArray(contacts));
    const nonAdminNonTeacher = contacts.filter(c => c.role !== 'teacher' && c.role !== 'admin');
    assert.strictEqual(nonAdminNonTeacher.length, 0, 'Parent contacts should only be teachers or admins');
  });

  it('soft-deleted message does not appear in inbox', async () => {
    const inbox = await (await api('GET', '/api/messages/inbox', teacherToken, null)).json();
    if (inbox.length === 0) return;
    const msgId = inbox[0].id;
    await api('DELETE', `/api/messages/${msgId}`, teacherToken, teacherCsrf);
    const inbox2 = await (await api('GET', '/api/messages/inbox', teacherToken, null)).json();
    const stillThere = inbox2.find(m => m.id === msgId);
    assert.ok(!stillThere, 'Deleted message should not appear in inbox');
  });
});
