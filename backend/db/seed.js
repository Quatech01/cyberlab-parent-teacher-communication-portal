'use strict';
const bcrypt = require('bcryptjs');

function seed(db) {
  const existingAdmin = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  if (existingAdmin) return;

  const pw = (plain) => bcrypt.hashSync(plain, 12);

  // Users: 1 admin, 3 teachers, 4 parents
  const insertUser = db.prepare(
    'INSERT OR IGNORE INTO users (username, email, password_hash, role, display_name) VALUES (?, ?, ?, ?, ?)'
  );

  insertUser.run('admin',       'admin@brookside.sch.uk',       pw('Admin@123'),   'admin',   'Admin');
  insertUser.run('mrs.smith',   'j.smith@brookside.sch.uk',     pw('Teacher@1'),   'teacher', 'Mrs J. Smith');
  insertUser.run('mr.jones',    'd.jones@brookside.sch.uk',     pw('Teacher@2'),   'teacher', 'Mr D. Jones');
  insertUser.run('miss.brown',  'a.brown@brookside.sch.uk',     pw('Teacher@3'),   'teacher', 'Miss A. Brown');
  insertUser.run('p.harris',    'p.harris@email.com',           pw('Parent@1'),    'parent',  'Paul Harris');
  insertUser.run('s.patel',     's.patel@email.com',            pw('Parent@2'),    'parent',  'Sunita Patel');
  insertUser.run('c.nguyen',    'c.nguyen@email.com',           pw('Parent@3'),    'parent',  'Christine Nguyen');
  insertUser.run('r.okafor',    'r.okafor@email.com',           pw('Parent@4'),    'parent',  'Richard Okafor');

  // Children
  const insertChild = db.prepare(
    'INSERT OR IGNORE INTO children (name, year_group, form_group) VALUES (?, ?, ?)'
  );
  insertChild.run('Emma Harris',    'Year 7', '7S');
  insertChild.run('Arjun Patel',    'Year 8', '8J');
  insertChild.run('Lily Nguyen',    'Year 7', '7S');
  insertChild.run('Kofi Okafor',    'Year 9', '9B');

  const userId  = (un) => db.prepare('SELECT id FROM users WHERE username = ?').get(un).id;
  const childId = (n)  => db.prepare('SELECT id FROM children WHERE name = ?').get(n).id;

  // Parent → child
  const insertPC = db.prepare('INSERT OR IGNORE INTO parent_children (parent_id, child_id) VALUES (?, ?)');
  insertPC.run(userId('p.harris'),  childId('Emma Harris'));
  insertPC.run(userId('s.patel'),   childId('Arjun Patel'));
  insertPC.run(userId('c.nguyen'),  childId('Lily Nguyen'));
  insertPC.run(userId('r.okafor'),  childId('Kofi Okafor'));

  // Teacher → child (Mrs Smith teaches Year 7, Mr Jones Year 8, Miss Brown Year 9)
  const insertTC = db.prepare('INSERT OR IGNORE INTO teacher_children (teacher_id, child_id) VALUES (?, ?)');
  insertTC.run(userId('mrs.smith'),  childId('Emma Harris'));
  insertTC.run(userId('mrs.smith'),  childId('Lily Nguyen'));
  insertTC.run(userId('mr.jones'),   childId('Arjun Patel'));
  insertTC.run(userId('miss.brown'), childId('Kofi Okafor'));

  // Sample announcements
  const insertAnn = db.prepare(
    'INSERT OR IGNORE INTO announcements (author_id, title, body, target_audience) VALUES (?, ?, ?, ?)'
  );
  insertAnn.run(userId('admin'),
    'Parent Evening — 20 November',
    'Parent evening appointments are now open for booking via the school website. Please log in to select your preferred slot.',
    'all');
  insertAnn.run(userId('mrs.smith'),
    'Year 7 Science Trip — Reminder',
    'Permission slips for the Science Museum trip on 5 December must be returned by Friday. Please ensure your child has their packed lunch.',
    'parents');

  // Sample messages
  const insertMsg = db.prepare(
    'INSERT OR IGNORE INTO messages (sender_id, recipient_id, subject, body) VALUES (?, ?, ?, ?)'
  );
  insertMsg.run(userId('p.harris'), userId('mrs.smith'),
    'Emma\'s reading progress',
    'Hi Mrs Smith, I wanted to ask how Emma is getting on with her reading targets this term. She seems to be enjoying the new books.');
  insertMsg.run(userId('mrs.smith'), userId('p.harris'),
    'RE: Emma\'s reading progress',
    'Hi Paul, Emma is doing wonderfully — she is currently reading above her target level. I\'ll share her latest assessment at parents\' evening.');
}

module.exports = { seed };
