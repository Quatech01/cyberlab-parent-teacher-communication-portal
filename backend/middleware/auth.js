'use strict';
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'cyberlab-dev-secret-change-in-prod';

function requireAuth(db) {
  return function (req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    const token = header.slice(7);
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      const user = db.prepare('SELECT id, username, email, role, display_name FROM users WHERE id = ?').get(payload.sub);
      if (!user) return res.status(401).json({ error: 'User not found' });
      req.user = user;
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  };
}

function requireCsrf(db) {
  return function (req, res, next) {
    if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) return next();
    const token = req.headers['x-csrf-token'];
    if (!token) return res.status(403).json({ error: 'CSRF token missing' });
    const stored = db.prepare('SELECT token FROM csrf_tokens WHERE user_id = ?').get(req.user.id);
    if (!stored || stored.token !== token) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    next();
  };
}

module.exports = { requireAuth, requireCsrf, JWT_SECRET };
