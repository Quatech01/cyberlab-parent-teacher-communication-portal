'use strict';

function requireRole(...roles) {
  return function (req, res, next) {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

function canSendMessage(db, senderId, senderRole, recipientId) {
  if (senderRole === 'admin') return true;

  if (senderRole === 'parent') {
    const link = db.prepare(`
      SELECT 1 FROM parent_children pc
      JOIN teacher_children tc ON pc.child_id = tc.child_id
      WHERE pc.parent_id = ? AND tc.teacher_id = ?
    `).get(senderId, recipientId);
    return !!link;
  }

  if (senderRole === 'teacher') {
    const link = db.prepare(`
      SELECT 1 FROM teacher_children tc
      JOIN parent_children pc ON tc.child_id = pc.child_id
      WHERE tc.teacher_id = ? AND pc.parent_id = ?
    `).get(senderId, recipientId);
    return !!link;
  }

  return false;
}

module.exports = { requireRole, canSendMessage };
