'use strict';
const express = require('express');
const { body, validationResult } = require('express-validator');
const { requireAuth, requireCsrf } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');

function createRouter(db) {
  const router = express.Router();
  const auth = requireAuth(db);
  const csrf = requireCsrf(db);

  // List announcements (all authenticated users)
  router.get('/', auth, (req, res) => {
    const rows = db.prepare(`
      SELECT a.id, a.title, a.body, a.target_audience, a.created_at,
             u.display_name AS author_name, u.role AS author_role
      FROM announcements a
      JOIN users u ON a.author_id = u.id
      ORDER BY a.created_at DESC
    `).all();
    return res.json(rows);
  });

  // Create announcement (admin or teacher)
  router.post('/', auth, csrf, requireRole('admin', 'teacher'), [
    body('title').trim().isLength({ min: 2, max: 200 }),
    body('body').trim().isLength({ min: 2, max: 5000 }),
    body('target_audience').optional().isIn(['all', 'parents', 'teachers', 'students']),
  ], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const { title, body: annBody, target_audience = 'all' } = req.body;
    const info = db.prepare(
      'INSERT INTO announcements (author_id, title, body, target_audience) VALUES (?, ?, ?, ?)'
    ).run(req.user.id, title.trim(), annBody.trim(), target_audience);

    db.prepare('INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)').run(
      req.user.id, 'create_announcement', `id=${info.lastInsertRowid}`
    );
    return res.status(201).json({ id: info.lastInsertRowid });
  });

  // Delete announcement (admin only)
  router.delete('/:id', auth, csrf, requireRole('admin'), (req, res) => {
    const ann = db.prepare('SELECT id FROM announcements WHERE id = ?').get(req.params.id);
    if (!ann) return res.status(404).json({ error: 'Announcement not found' });
    db.prepare('DELETE FROM announcements WHERE id = ?').run(req.params.id);
    return res.json({ ok: true });
  });

  return router;
}

module.exports = { createRouter };
