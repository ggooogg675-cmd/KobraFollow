const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const crypto = require('node:crypto');
const db = require('./db');

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN || false }));
app.use(express.json({ limit: '32kb' }));

const platforms = new Set(['instagram', 'tiktok']);
const hashToken = token =>
  crypto.createHash('sha256').update(token).digest('hex');

function makePassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return salt.toString('hex') + ':' + hash.toString('hex');
}

function checkPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [saltHex, hashHex] = stored.split(':');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), 64);
  return expected.length === actual.length &&
    crypto.timingSafeEqual(expected, actual);
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'login required' });

  const session = db.prepare(`
    SELECT sessions.user_id AS userId
    FROM sessions
    WHERE token_hash = ? AND expires_at > ?
  `).get(hashToken(token), Date.now());

  if (!session) return res.status(401).json({ error: 'invalid or expired session' });
  req.userId = session.userId;
  next();
}

function adminOnly(req, res, next) {
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.userId);
  if (!user || user.role !== 'admin')
    return res.status(403).json({ error: 'غير مسموح؛ هذه الصفحة للمدير فقط' });
  next();
}

app.get('/health', (_req, res) =>
  res.json({ ok: true, service: 'kobra-follow-api' })
);

app.post('/api/register', (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!/^[a-z0-9_]{3,24}$/.test(username))
    return res.status(400).json({ error: 'اسم المستخدم يجب أن يكون 3 إلى 24 حرفاً أو رقماً أو _' });

  if (password.length < 8 || password.length > 128)
    return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل' });

  try {
    const result = db.prepare(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)'
    ).run(username, makePassword(password));

    const userId = Number(result.lastInsertRowid);
    const token = crypto.randomBytes(32).toString('hex');

    db.prepare(
      'INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)'
    ).run(userId, hashToken(token), Date.now() + 7 * 86400000);

    res.status(201).json({
      token,
      user: db.prepare('SELECT id, username, coins, role FROM users WHERE id = ?').get(userId)
    });
  } catch {
    res.status(409).json({ error: 'اسم المستخدم مستخدم بالفعل' });
  }
});

app.post('/api/login', (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user || !checkPassword(password, user.password_hash))
    return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });

  const token = crypto.randomBytes(32).toString('hex');

  db.prepare(
    'INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)'
  ).run(user.id, hashToken(token), Date.now() + 7 * 86400000);

  res.json({
    token,
    user: { id: user.id, username: user.username, coins: user.coins, role: user.role }
  });
});

app.post('/api/logout', auth, (req, res) => {
  const token = req.headers.authorization.slice(7);
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare(
    'SELECT id, username, coins, created_at, role FROM users WHERE id = ?'
  ).get(req.userId);
  res.json(user);
});

app.get('/api/wallet', auth, (req, res) => {
  const user = db.prepare(
    'SELECT id, username, coins FROM users WHERE id = ?'
  ).get(req.userId);

  const transactions = db.prepare(
    'SELECT amount, reason, created_at FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 50'
  ).all(req.userId);

  res.json({ ...user, transactions });
});

app.get('/api/tasks', auth, (req, res) => {
  const platform = req.query.platform;
  if (platform && !platforms.has(platform))
    return res.status(400).json({ error: 'unsupported platform' });

  const tasks = platform
    ? db.prepare("SELECT id, platform, task_type, title, reward FROM tasks WHERE status='active' AND platform=? ORDER BY id DESC").all(platform)
    : db.prepare("SELECT id, platform, task_type, title, reward FROM tasks WHERE status='active' ORDER BY id DESC").all();

  res.json(tasks);
});

app.post('/api/tasks/:id/submit', auth, (req, res) => {
  const taskId = Number(req.params.id);

  if (!Number.isInteger(taskId) || taskId < 1)
    return res.status(400).json({ error: 'رقم المهمة غير صحيح' });

  const task = db.prepare(
    "SELECT id FROM tasks WHERE id = ? AND status = 'active'"
  ).get(taskId);

  if (!task)
    return res.status(404).json({ error: 'المهمة غير موجودة أو غير متاحة' });

  try {
    const result = db.prepare(
      'INSERT INTO task_submissions (user_id, task_id) VALUES (?, ?)'
    ).run(req.userId, taskId);

    res.status(201).json({
      id: Number(result.lastInsertRowid),
      status: 'pending',
      message: 'تم إرسال المهمة للمراجعة'
    });
  } catch (error) {
    if (String(error.message).includes('UNIQUE'))
      return res.status(409).json({ error: 'سبق لك إرسال هذه المهمة' });
    throw error;
  }
});

app.get('/api/task-submissions', auth, (req, res) => {
  const submissions = db.prepare(`
    SELECT s.id, s.task_id, t.title, t.reward, s.status, s.created_at
    FROM task_submissions s
    JOIN tasks t ON t.id = s.task_id
    WHERE s.user_id = ?
    ORDER BY s.id DESC
  `).all(req.userId);

  res.json(submissions);
});

app.get('/api/requests', auth, (req, res) => {
  res.json(db.prepare(
    'SELECT id, platform, request_type, target_handle, quantity, status, created_at FROM requests WHERE user_id = ? ORDER BY id DESC'
  ).all(req.userId));
});

app.post('/api/requests', auth, (req, res) => {
  const platform = String(req.body.platform || '');
  const requestType = String(req.body.requestType || '');
  const targetHandle = String(req.body.targetHandle || '').trim().replace(/^@/, '');
  const quantity = Number(req.body.quantity);

  if (!platforms.has(platform))
    return res.status(400).json({ error: 'unsupported platform' });

  if (!['followers_campaign', 'likes_campaign'].includes(requestType))
    return res.status(400).json({ error: 'invalid request type' });

  if (!/^[a-zA-Z0-9._]{2,30}$/.test(targetHandle))
    return res.status(400).json({ error: 'invalid public handle' });

  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 10000)
    return res.status(400).json({ error: 'quantity must be 1-10000' });

  const result = db.prepare(
    'INSERT INTO requests (user_id, platform, request_type, target_handle, quantity) VALUES (?, ?, ?, ?, ?)'
  ).run(req.userId, platform, requestType, targetHandle, quantity);

  res.status(201).json(
    db.prepare('SELECT * FROM requests WHERE id = ?').get(result.lastInsertRowid)
  );
});


// لوحة مراجعة المدير
app.get('/api/admin/submissions', auth, adminOnly, (_req, res) => {
  const rows = db.prepare(`
    SELECT s.id, s.user_id, u.username, s.task_id, t.title,
           t.platform, t.reward, s.status, s.created_at
    FROM task_submissions s
    JOIN users u ON u.id = s.user_id
    JOIN tasks t ON t.id = s.task_id
    ORDER BY CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END, s.id DESC
  `).all();
  res.json(rows);
});

// اعتماد المهمة وصرف المكافأة مرة واحدة فقط
app.post('/api/admin/submissions/:id/approve', auth, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1)
    return res.status(400).json({ error: 'رقم الإرسال غير صحيح' });

  try {
    db.exec('BEGIN IMMEDIATE');

    const submission = db.prepare(`
      SELECT s.id, s.user_id, s.status, t.reward, t.title
      FROM task_submissions s
      JOIN tasks t ON t.id = s.task_id
      WHERE s.id = ?
    `).get(id);

    if (!submission) {
      db.exec('ROLLBACK');
      return res.status(404).json({ error: 'المهمة المرسلة غير موجودة' });
    }

    if (submission.status !== 'pending') {
      db.exec('ROLLBACK');
      return res.status(409).json({ error: 'تمت مراجعة هذه المهمة من قبل' });
    }

    db.prepare("UPDATE task_submissions SET status = 'approved' WHERE id = ? AND status = 'pending'").run(id);
    db.prepare('UPDATE users SET coins = coins + ? WHERE id = ?').run(submission.reward, submission.user_id);
    db.prepare('INSERT INTO transactions (user_id, amount, reason) VALUES (?, ?, ?)')
      .run(submission.user_id, submission.reward, 'مكافأة اعتماد المهمة: ' + submission.title);

    db.exec('COMMIT');
    res.json({ ok: true, message: 'تم اعتماد المهمة وصرف النقاط', reward: submission.reward });
  } catch (error) {
    try { db.exec('ROLLBACK'); } catch {}
    console.error(error);
    res.status(500).json({ error: 'تعذر اعتماد المهمة' });
  }
});

// رفض المهمة بدون صرف نقاط
app.post('/api/admin/submissions/:id/reject', auth, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1)
    return res.status(400).json({ error: 'رقم الإرسال غير صحيح' });

  const result = db.prepare(
    "UPDATE task_submissions SET status = 'rejected' WHERE id = ? AND status = 'pending'"
  ).run(id);

  if (!result.changes)
    return res.status(409).json({ error: 'المهمة غير موجودة أو تمت مراجعتها بالفعل' });

  res.json({ ok: true, message: 'تم رفض المهمة بدون إضافة نقاط' });
});

app.use(express.static('public'));

const port = Number(process.env.PORT || 3000);
app.listen(port, () =>
  console.log(`Kobra Follow API listening on ${port}`)
);
