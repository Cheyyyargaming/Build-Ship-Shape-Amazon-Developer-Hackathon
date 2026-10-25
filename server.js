'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const {
  createHash,
  randomBytes,
  scrypt,
  timingSafeEqual,
} = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const DB_PATH = path.join(ROOT, 'aha-academy.sqlite');
const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 4173);
const SESSION_COOKIE = 'aha_session';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const ALLOWED_GRADES = new Set(['Grade 3', 'Grade 4', 'Grade 5', 'Grade 6', 'Grade 7', 'Grade 8']);
const EXTRA_LESSON_SEEDS = require('./lesson-data');
const ALLOWED_LESSONS = new Set(['fractions', 'solar', 'cleopatra', 'transit', 'similes', ...EXTRA_LESSON_SEEDS.map(seed => seed[0])]);
const ALLOWED_TASKS = new Set(['warmup', 'lesson', 'teachback']);
const loginAttempts = new Map();

const db = new DatabaseSync(DB_PATH);
db.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    grade TEXT NOT NULL,
    password_salt BLOB NOT NULL,
    password_hash BLOB NOT NULL,
    created_at INTEGER NOT NULL
  ) STRICT;
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  ) STRICT;
  CREATE TABLE IF NOT EXISTS lesson_progress (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lesson_id TEXT NOT NULL,
    completed_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, lesson_id)
  ) STRICT;
  CREATE TABLE IF NOT EXISTS daily_tasks (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    task_date TEXT NOT NULL,
    task_id TEXT NOT NULL,
    completed_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, task_date, task_id)
  ) STRICT;
`);

const statements = {
  userByName: db.prepare('SELECT id, username, grade, password_salt, password_hash FROM users WHERE username = ?'),
  userById: db.prepare('SELECT id, username, grade FROM users WHERE id = ?'),
  insertUser: db.prepare('INSERT INTO users (username, grade, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)'),
  insertSession: db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)'),
  sessionUser: db.prepare(`SELECT users.id, users.username, users.grade, sessions.expires_at
    FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ?`),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
  deleteExpired: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
  listLessons: db.prepare('SELECT lesson_id FROM lesson_progress WHERE user_id = ? ORDER BY completed_at'),
  saveLesson: db.prepare(`INSERT INTO lesson_progress (user_id, lesson_id, completed_at) VALUES (?, ?, ?)
    ON CONFLICT(user_id, lesson_id) DO NOTHING`),
  listTasks: db.prepare('SELECT task_id FROM daily_tasks WHERE user_id = ? AND task_date = ? ORDER BY task_id'),
  saveTask: db.prepare(`INSERT INTO daily_tasks (user_id, task_date, task_id, completed_at) VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, task_date, task_id) DO UPDATE SET completed_at = excluded.completed_at`),
  deleteTask: db.prepare('DELETE FROM daily_tasks WHERE user_id = ? AND task_date = ? AND task_id = ?'),
};

function json(res, status, value, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...securityHeaders(),
    ...extraHeaders,
  });
  res.end(JSON.stringify(value));
}

function securityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
  };
}

function fail(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function safeEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function derivePassword(password, salt) {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, 64, { N: 1 << 14, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (error, key) => {
      if (error) reject(error);
      else resolve(key);
    });
  });
}

function validDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 10) === value;
}

function checkOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return;
  let parsed;
  try { parsed = new URL(origin); } catch { throw fail(403, 'Request origin is not allowed.'); }
  if (parsed.origin === 'null' || parsed.host !== req.headers.host) throw fail(403, 'Request origin is not allowed.');
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooLarge = false;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > 4096) { tooLarge = true; return; }
      if (!tooLarge) chunks.push(chunk);
    });
    req.on('error', reject);
    req.on('end', () => {
      if (tooLarge) return reject(fail(413, 'Request is too large.'));
      try {
        const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error('not an object');
        resolve(parsed);
      } catch { reject(fail(400, 'Please send valid JSON.')); }
    });
  });
}

function checkRateLimit(req) {
  const key = req.socket.remoteAddress || 'local';
  const now = Date.now();
  const current = loginAttempts.get(key);
  const windowMs = 15 * 60 * 1000;
  if (!current || now - current.startedAt > windowMs) {
    loginAttempts.set(key, { startedAt: now, count: 1 });
    return;
  }
  if (current.count >= 10) throw fail(429, 'Too many sign-in attempts. Please wait a few minutes and try again.');
  current.count += 1;
}

function cookieToken(req) {
  const cookie = (req.headers.cookie || '').split(';').map(part => part.trim()).find(part => part.startsWith(`${SESSION_COOKIE}=`));
  return cookie ? cookie.slice(SESSION_COOKIE.length + 1) : '';
}

function sessionFor(req) {
  const token = cookieToken(req);
  if (!/^[A-Za-z0-9_-]{30,}$/.test(token)) return null;
  const tokenHash = createHash('sha256').update(token).digest('hex');
  const row = statements.sessionUser.get(tokenHash);
  if (!row) return null;
  if (row.expires_at <= Date.now()) {
    statements.deleteSession.run(tokenHash);
    return null;
  }
  return { id: row.id, username: row.username, grade: row.grade, tokenHash };
}

function setSessionCookie(res, token, maxAge) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`);
}

function createSession(res, userId) {
  statements.deleteExpired.run(Date.now());
  const token = randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const tokenHash = createHash('sha256').update(token).digest('hex');
  statements.insertSession.run(tokenHash, userId, expiresAt);
  setSessionCookie(res, token, Math.floor(SESSION_TTL_MS / 1000));
}

function publicUser(user) {
  return { username: user.username, grade: user.grade };
}

async function apiRoute(req, res, url) {
  const route = url.pathname;
  if (req.method === 'GET' && route === '/api/me') {
    const user = sessionFor(req);
    if (!user) return json(res, 401, { error: 'Please sign in.' });
    return json(res, 200, { user: publicUser(user) });
  }

  if (req.method === 'POST' && ['/api/register', '/api/login', '/api/logout', '/api/progress/lesson', '/api/progress/task'].includes(route)) {
    checkOrigin(req);
  }

  if (req.method === 'POST' && (route === '/api/register' || route === '/api/login')) {
    checkRateLimit(req);
    if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '')) throw fail(415, 'Please send JSON data.');
    const body = await readJson(req);
    const username = typeof body.username === 'string' ? body.username.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    if (!/^[A-Za-z0-9_]{3,20}$/.test(username)) throw fail(400, 'Username must be 3–20 letters, numbers, or underscores.');
    if (password.length < 8 || Buffer.byteLength(password, 'utf8') > 128) throw fail(400, 'Password must be at least 8 characters and no more than 128 bytes.');

    if (route === '/api/register') {
      const grade = body.grade;
      if (!ALLOWED_GRADES.has(grade)) throw fail(400, 'Choose a school grade from the list.');
      const salt = randomBytes(16);
      const passwordHash = await derivePassword(password, salt);
      try {
        const result = statements.insertUser.run(username, grade, salt, passwordHash, Date.now());
        createSession(res, Number(result.lastInsertRowid));
        return json(res, 201, { user: { username, grade } });
      } catch (error) {
        if (String(error.message || '').includes('UNIQUE constraint failed: users.username')) throw fail(409, 'That username is taken. Please choose another.');
        throw error;
      }
    }

    const user = statements.userByName.get(username);
    const salt = user ? Buffer.from(user.password_salt) : Buffer.from('aha-academy-dummy-password-salt');
    const calculated = await derivePassword(password, salt);
    const matches = user ? safeEqual(calculated, Buffer.from(user.password_hash)) : false;
    if (!matches) throw fail(401, 'Username or password is incorrect.');
    createSession(res, user.id);
    return json(res, 200, { user: publicUser(user) });
  }

  if (req.method === 'POST' && route === '/api/logout') {
    const user = sessionFor(req);
    if (user) statements.deleteSession.run(user.tokenHash);
    setSessionCookie(res, '', 0);
    return json(res, 200, { ok: true });
  }

  if ((req.method === 'GET' && route === '/api/progress') || (req.method === 'POST' && (route === '/api/progress/lesson' || route === '/api/progress/task'))) {
    const user = sessionFor(req);
    if (!user) throw fail(401, 'Please sign in again.');
    if (req.method === 'GET') {
      const date = url.searchParams.get('date');
      if (!validDate(date)) throw fail(400, 'A valid local date is required.');
      return json(res, 200, {
        completedLessons: statements.listLessons.all(user.id).map(row => row.lesson_id),
        dailyTasks: statements.listTasks.all(user.id, date).map(row => row.task_id),
      });
    }
    if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '')) throw fail(415, 'Please send JSON data.');
    const body = await readJson(req);
    if (route === '/api/progress/lesson') {
      if (!ALLOWED_LESSONS.has(body.lessonId)) throw fail(400, 'That lesson is not available.');
      statements.saveLesson.run(user.id, body.lessonId, Date.now());
    } else {
      if (!validDate(body.date) || !ALLOWED_TASKS.has(body.taskId) || typeof body.completed !== 'boolean') throw fail(400, 'That task update is not valid.');
      if (body.completed) statements.saveTask.run(user.id, body.date, body.taskId, Date.now());
      else statements.deleteTask.run(user.id, body.date, body.taskId);
    }
    return json(res, 200, { ok: true });
  }

  return json(res, 404, { error: 'Not found.' });
}

function serveApp(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { error: 'Method not allowed.' });
  if (url.pathname === '/lesson-data.js') {
    res.writeHead(200, {
      'Content-Type': 'text/javascript; charset=utf-8',
      'Cache-Control': 'no-cache',
      ...securityHeaders(),
    });
    if (req.method === 'HEAD') return res.end();
    return fs.createReadStream(path.join(ROOT, 'lesson-data.js')).pipe(res);
  }
  if (url.pathname !== '/' && url.pathname !== '/index.html') return json(res, 404, { error: 'Not found.' });
  const filePath = path.join(ROOT, 'index.html');
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-cache',
    ...securityHeaders(),
  });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(filePath).pipe(res);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname.startsWith('/api/')) await apiRoute(req, res, url);
    else serveApp(req, res, url);
  } catch (error) {
    if (res.headersSent) return res.destroy();
    const status = Number.isInteger(error.status) ? error.status : 500;
    if (status === 500) console.error('Aha Academy request failed.');
    json(res, status, { error: status === 500 ? 'Something went wrong. Please try again.' : error.message });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Aha Academy is running at http://${HOST}:${PORT}`);
  console.log(`SQLite database: ${DB_PATH}`);
});
