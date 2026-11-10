'use strict';
const express = require('express');
const { body, validationResult } = require('express-validator');
const { requireAuth, requireCsrf } = require('../middleware/auth');
const { canSendMessage } = require('../middleware/rbac');

function createRouter(db) {
  const router = express.Router();
  const auth = requireAuth(db);
  const csrf = requireCsrf(db);

  // List inbox
  router.get('/inbox', auth, (req, res) => {
    const rows = db.prepare(`
      SELECT m.id, m.subject, m.body, m.is_read, m.created_at,
             u.id AS sender_id, u.display_name AS sender_name, u.role AS sender_role
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.recipient_id = ? AND m.recipient_deleted = 0
      ORDER BY m.created_at DESC
    `).all(req.user.id);
    return res.json(rows);
  });

  // List sent
  router.get('/sent', auth, (req, res) => {
    const rows = db.prepare(`
      SELECT m.id, m.subject, m.body, m.is_read, m.created_at,
             u.id AS recipient_id, u.display_name AS recipient_name, u.role AS recipient_role
      FROM messages m
      JOIN users u ON m.recipient_id = u.id
      WHERE m.sender_id = ? AND m.sender_deleted = 0
      ORDER BY m.created_at DESC
    `).all(req.user.id);
    return res.json(rows);
  });

  // Unread count
  router.get('/unread-count', auth, (req, res) => {
    const row = db.prepare('SELECT COUNT(*) AS count FROM messages WHERE recipient_id = ? AND is_read = 0 AND recipient_deleted = 0').get(req.user.id);
    return res.json({ count: row.count });
  });

  // List contacts this user may message
  router.get('/contacts', auth, (req, res) => {
    let rows;
    if (req.user.role === 'admin') {
      rows = db.prepare('SELECT id, display_name, role FROM users WHERE id != ? ORDER BY role, display_name').all(req.user.id);
    } else if (req.user.role === 'parent') {
      rows = db.prepare(`
        SELECT DISTINCT u.id, u.display_name, u.role
        FROM users u
        JOIN teacher_children tc ON u.id = tc.teacher_id
        JOIN parent_children pc ON tc.child_id = pc.child_id
        WHERE pc.parent_id = ? AND u.role = 'teacher'
        ORDER BY u.display_name
      `).all(req.user.id);
      // include admin
      const admins = db.prepare("SELECT id, display_name, role FROM users WHERE role = 'admin'").all();
      rows = [...rows, ...admins];
    } else if (req.user.role === 'teacher') {
      rows = db.prepare(`
        SELECT DISTINCT u.id, u.display_name, u.role
        FROM users u
        JOIN parent_children pc ON u.id = pc.parent_id
        JOIN teacher_children tc ON pc.child_id = tc.child_id
        WHERE tc.teacher_id = ? AND u.role = 'parent'
        ORDER BY u.display_name
      `).all(req.user.id);
      const admins = db.prepare("SELECT id, display_name, role FROM users WHERE role = 'admin'").all();
      rows = [...rows, ...admins];
    } else {
      rows = [];
    }
    return res.json(rows);
  });

  // Send message
  router.post('/send', auth, csrf, [
    body('recipient_id').isInt({ min: 1 }),
    body('subject').trim().isLength({ min: 1, max: 200 }),
    body('body').trim().isLength({ min: 1, max: 5000 }),
  ], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(422).json({ errors: errors.array() });

    const { recipient_id, subject, body: msgBody } = req.body;
    const recipient = db.prepare('SELECT id, role FROM users WHERE id = ?').get(recipient_id);
    if (!recipient) return res.status(404).json({ error: 'Recipient not found' });

    if (!canSendMessage(db, req.user.id, req.user.role, recipient_id)) {
      return res.status(403).json({ error: 'You are not permitted to message this user' });
    }

    const info = db.prepare(
      'INSERT INTO messages (sender_id, recipient_id, subject, body) VALUES (?, ?, ?, ?)'
    ).run(req.user.id, recipient_id, subject.trim(), msgBody.trim());

    db.prepare('INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)').run(
      req.user.id, 'send_message', `to=${recipient_id}`
    );
    return res.status(201).json({ id: info.lastInsertRowid });
  });

  // Mark as read
  router.put('/:id/read', auth, csrf, (req, res) => {
    const msg = db.prepare('SELECT * FROM messages WHERE id = ? AND recipient_id = ?').get(req.params.id, req.user.id);
    if (!msg) return res.status(404).json({ error: 'Message not found' });
    db.prepare('UPDATE messages SET is_read = 1 WHERE id = ?').run(req.params.id);
    return res.json({ ok: true });
  });

  // Delete (soft delete)
  router.delete('/:id', auth, csrf, (req, res) => {
    const msgAsRecipient = db.prepare('SELECT * FROM messages WHERE id = ? AND recipient_id = ?').get(req.params.id, req.user.id);
    const msgAsSender    = db.prepare('SELECT * FROM messages WHERE id = ? AND sender_id = ?').get(req.params.id, req.user.id);
    if (!msgAsRecipient && !msgAsSender) return res.status(404).json({ error: 'Message not found' });
    if (msgAsRecipient) db.prepare('UPDATE messages SET recipient_deleted = 1 WHERE id = ?').run(req.params.id);
    if (msgAsSender)    db.prepare('UPDATE messages SET sender_deleted = 1 WHERE id = ?').run(req.params.id);
    return res.json({ ok: true });
  });

  return router;
}

module.exports = { createRouter };
