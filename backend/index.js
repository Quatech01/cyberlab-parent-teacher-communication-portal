'use strict';
const express = require('express');
const helmet  = require('helmet');
const rateLimit = require('express-rate-limit');
const path  = require('node:path');
const fs    = require('node:fs');
const { DatabaseSync } = require('node:sqlite');

const { seed }   = require('./db/seed');
const authRoutes = require('./routes/auth');
const msgRoutes  = require('./routes/messages');
const annRoutes  = require('./routes/announcements');

function initDb(dbPath) {
  const db = new DatabaseSync(dbPath);
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('PRAGMA journal_mode = WAL');
  const schema = fs.readFileSync(path.join(__dirname, 'db', 'schema.sql'), 'utf-8');
  db.exec(schema);
  seed(db);
  return db;
}

function createApp(db) {
  const app = express();

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc:  ["'self'", "'unsafe-inline'"],
        styleSrc:   ["'self'", "'unsafe-inline'"],
        imgSrc:     ["'self'", 'data:'],
      }
    },
    hsts: { maxAge: 31536000, includeSubDomains: true },
  }));

  app.use(express.json({ limit: '64kb' }));

  app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests' } }));
  app.use('/api/',     rateLimit({ windowMs: 60 * 1000,      max: 100, standardHeaders: true, legacyHeaders: false }));

  app.get('/health', (_req, res) => res.json({ status: 'ok' }));

  app.use('/api/auth',          authRoutes.createRouter(db));
  app.use('/api/messages',      msgRoutes.createRouter(db));
  app.use('/api/announcements', annRoutes.createRouter(db));

  app.use(express.static(path.join(__dirname, '..', 'frontend')));
  app.get('*', (_req, res) => res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html')));

  return app;
}

function start(port = 3000, { dbPath = path.join(__dirname, 'cyberlab.db') } = {}) {
  const db  = initDb(dbPath);
  const app = createApp(db);
  return new Promise((resolve) => {
    const server = app.listen(port, '127.0.0.1', () => resolve(server));
  });
}

module.exports = { start, createApp, initDb };

if (require.main === module) {
  start(3000).then(() => console.log('Server running on http://127.0.0.1:3000'));
}
