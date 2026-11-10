'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');
const { body, validationResult } = require('express-validator');
const { requireAuth, JWT_SECRET } = require('../middleware/auth');

const ACCESS_EXPIRY  = '15m';
const REFRESH_EXPIRY = '7d';

function signAccess(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: ACCESS_EXPIRY, algorithm: 'HS256' });
}
function signRefresh(userId) {
  // jti ensures uniqueness even if called multiple times within the same second
  return jwt.sign({ sub: userId, jti: crypto.randomBytes(16).toString('hex') }, JWT_SECRET, { expiresIn: REFRESH_EXPIRY, algorithm: 'HS256' });
}

function createRouter(db) {
  const router = express.Router();

  router.post('/register', [
    body('username').trim().isLength({ min: 3, max: 30 }).matches(/^[a-zA-Z0-9._-]+$/),
    body('email').trim().isEmail().normalizeEmail(),
    body('password').isLength({ min: 8, max: 72 }),
    body('display_name').trim().isLength({ min: 2, max: 60 }),
    body('role').optional().isIn(['parent', 'teacher']),
  ], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const { username, email, password, display_name, role = 'parent' } = req.body;
    const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
    if (existing) return res.status(409).json({ error: 'Username or email already in use' });

    const hash = bcrypt.hashSync(password, 12);
    const info = db.prepare(
      'INSERT INTO users (username, email, password_hash, role, display_name) VALUES (?, ?, ?, ?, ?)'
    ).run(username, email, hash, role, display_name);

    db.prepare('INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)').run(
      info.lastInsertRowid, 'register', `role=${role}`
    );
    return res.status(201).json({ id: info.lastInsertRowid, username, role });
  });

  router.post('/login', [
    body('username').trim().notEmpty(),
    body('password').notEmpty(),
  ], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(username, username);
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const accessToken  = signAccess(user.id);
    const refreshToken = signRefresh(user.id);
    const expiresAt    = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, refreshToken, expiresAt);

    const csrfToken = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO csrf_tokens (user_id, token) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET token = ?, created_at = CURRENT_TIMESTAMP').run(user.id, csrfToken, csrfToken);

    db.prepare('INSERT INTO audit_log (user_id, action) VALUES (?, ?)').run(user.id, 'login');
    return res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      csrf_token: csrfToken,
      user: { id: user.id, username: user.username, email: user.email, role: user.role, display_name: user.display_name }
    });
  });

  router.post('/refresh', (req, res) => {
    const { refresh_token } = req.body;
    if (!refresh_token) return res.status(400).json({ error: 'refresh_token required' });

    const record = db.prepare('SELECT * FROM refresh_tokens WHERE token = ? AND revoked = 0').get(refresh_token);
    if (!record) return res.status(401).json({ error: 'Invalid or revoked refresh token' });
    if (new Date(record.expires_at) < new Date()) return res.status(401).json({ error: 'Refresh token expired' });

    try {
      const payload = jwt.verify(refresh_token, JWT_SECRET);
      const newAccess  = signAccess(payload.sub);
      const newRefresh = signRefresh(payload.sub);
      const expiresAt  = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

      db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?').run(record.id);
      db.prepare('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(record.user_id, newRefresh, expiresAt);

      return res.json({ access_token: newAccess, refresh_token: newRefresh });
    } catch {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
  });

  router.post('/logout', requireAuth(db), (req, res) => {
    const { refresh_token } = req.body;
    if (refresh_token) {
      db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token = ? AND user_id = ?').run(refresh_token, req.user.id);
    }
    db.prepare('DELETE FROM csrf_tokens WHERE user_id = ?').run(req.user.id);
    db.prepare('INSERT INTO audit_log (user_id, action) VALUES (?, ?)').run(req.user.id, 'logout');
    return res.json({ message: 'Logged out' });
  });

  router.get('/me', requireAuth(db), (req, res) => {
    return res.json(req.user);
  });

  return router;
}

module.exports = { createRouter };
