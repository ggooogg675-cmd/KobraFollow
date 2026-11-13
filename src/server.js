require('dotenv').config();

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
  const actual = crypto.scryptSync(
    password,
    Buffer.from(saltHex, 'hex'),
    64
  );

  return expected.length === actual.length &&
    crypto.timingSafeEqual(expected, actual);
}

function numbers(row) {
  if (!row) return row;

  const fields = [
    'id', 'user_id', 'task_id', 'coins',
    'reward', 'amount', 'quantity', 'expires_at'
  ];

  for (const field of fields) {
    if (row[field] !== undefined && row[field] !== null) {
      row[field] = Number(row[field]);
    }
  }

  return row;
}

function asyncRoute(fn) {
  return (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);
}

const auth = asyncRoute(async (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';

  if (!token) {
    return res.status(401).json({ error: 'login required' });
  }

  const result = await db.query(`
    SELECT user_id
    FROM sessions
    WHERE token_hash = $1 AND expires_at > $2
  `, [hashToken(token), Date.now()]);

  if (!result.rows.length) {
    return res.status(401).json({
      error: 'invalid or expired session'
    });
  }

  req.userId = Number(result.rows[0].user_id);
  next();
});

const adminOnly = asyncRoute(async (req, res, next) => {
  const result = await db.query(
    'SELECT role FROM users WHERE id = $1',
    [req.userId]
  );

  if (!result.rows.length || result.rows[0].role !== 'admin') {
    return res.status(403).json({
      error: 'غير مسموح؛ هذه الصفحة للمدير فقط'
    });
  }

  next();
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'kobra-follow-api' });
});

// إنشاء حساب
app.post('/api/register', asyncRoute(async (req, res) => {
  const username = String(req.body.username || '')
    .trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!/^[a-z0-9_]{3,24}$/.test(username)) {
    return res.status(400).json({
      error: 'اسم المستخدم يجب أن يكون 3 إلى 24 حرفاً أو رقماً أو _'
    });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({
      error: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل'
    });
  }

  const client = await db.connect();

  try {
    await client.query('BEGIN');

    const inserted = await client.query(
      `INSERT INTO users (username, password_hash)
       VALUES ($1, $2)
       RETURNING id, username, coins, role`,
      [username, makePassword(password)]
    );

    const user = numbers(inserted.rows[0]);
    const token = crypto.randomBytes(32).toString('hex');

    await client.query(
      `INSERT INTO sessions (user_id, token_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [user.id, hashToken(token), Date.now() + 7 * 86400000]
    );

    await client.query('COMMIT');

    res.status(201).json({ token, user });
  } catch (error) {
    await client.query('ROLLBACK');

    if (error.code === '23505') {
      return res.status(409).json({
        error: 'اسم المستخدم مستخدم بالفعل'
      });
    }

    throw error;
  } finally {
    client.release();
  }
}));

// تسجيل الدخول
app.post('/api/login', asyncRoute(async (req, res) => {
  const username = String(req.body.username || '')
    .trim().toLowerCase();
  const password = String(req.body.password || '');

  const result = await db.query(
    'SELECT * FROM users WHERE username = $1',
    [username]
  );

  const user = result.rows[0];

  if (!user || !checkPassword(password, user.password_hash)) {
    return res.status(401).json({
      error: 'اسم المستخدم أو كلمة المرور غير صحيحة'
    });
  }

  const token = crypto.randomBytes(32).toString('hex');

  await db.query(
    `INSERT INTO sessions (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)`,
    [user.id, hashToken(token), Date.now() + 7 * 86400000]
  );

  res.json({
    token,
    user: numbers({
      id: user.id,
      username: user.username,
      coins: user.coins,
      role: user.role
    })
  });
}));

// تسجيل الخروج
app.post('/api/logout', auth, asyncRoute(async (req, res) => {
  const token = req.headers.authorization.slice(7);

  await db.query(
    'DELETE FROM sessions WHERE token_hash = $1',
    [hashToken(token)]
  );

  res.json({ ok: true });
}));

// بيانات الحساب
app.get('/api/me', auth, asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT id, username, coins, created_at, role
     FROM users WHERE id = $1`,
    [req.userId]
  );

  res.json(numbers(result.rows[0]));
}));

// المحفظة
app.get('/api/wallet', auth, asyncRoute(async (req, res) => {
  const userResult = await db.query(
    'SELECT id, username, coins FROM users WHERE id = $1',
    [req.userId]
  );

  const txResult = await db.query(
    `SELECT amount, reason, created_at
     FROM transactions
     WHERE user_id = $1
     ORDER BY id DESC LIMIT 50`,
    [req.userId]
  );

  res.json({
    ...numbers(userResult.rows[0]),
    transactions: txResult.rows.map(numbers)
  });
}));

// عرض المهام
app.get('/api/tasks', auth, asyncRoute(async (req, res) => {
  const platform = req.query.platform;

  if (platform && !platforms.has(platform)) {
    return res.status(400).json({
      error: 'unsupported platform'
    });
  }

  const result = platform
    ? await db.query(
        `SELECT id, platform, task_type, title, reward
         FROM tasks
         WHERE status = 'active' AND platform = $1
         ORDER BY id DESC`,
        [platform]
      )
    : await db.query(
        `SELECT id, platform, task_type, title, reward
         FROM tasks
         WHERE status = 'active'
         ORDER BY id DESC`
      );

  res.json(result.rows.map(numbers));
}));

// إرسال مهمة للمراجعة
app.post('/api/tasks/:id/submit', auth,
  asyncRoute(async (req, res) => {
    const taskId = Number(req.params.id);

    if (!Number.isInteger(taskId) || taskId < 1) {
      return res.status(400).json({
        error: 'رقم المهمة غير صحيح'
      });
    }

    const task = await db.query(
      `SELECT id FROM tasks
       WHERE id = $1 AND status = 'active'`,
      [taskId]
    );

    if (!task.rows.length) {
      return res.status(404).json({
        error: 'المهمة غير موجودة أو غير متاحة'
      });
    }

    try {
      const result = await db.query(
        `INSERT INTO task_submissions (user_id, task_id)
         VALUES ($1, $2) RETURNING id`,
        [req.userId, taskId]
      );

      res.status(201).json({
        id: Number(result.rows[0].id),
        status: 'pending',
        message: 'تم إرسال المهمة للمراجعة'
      });
    } catch (error) {
      if (error.code === '23505') {
        return res.status(409).json({
          error: 'سبق لك إرسال هذه المهمة'
        });
      }

      throw error;
    }
  })
);

// سجل المهام المرسلة
app.get('/api/task-submissions', auth,
  asyncRoute(async (req, res) => {
    const result = await db.query(`
      SELECT s.id, s.task_id, t.title, t.reward,
             s.status, s.created_at
      FROM task_submissions s
      JOIN tasks t ON t.id = s.task_id
      WHERE s.user_id = $1
      ORDER BY s.id DESC
    `, [req.userId]);

    res.json(result.rows.map(numbers));
  })
);

// عرض الطلبات
app.get('/api/requests', auth, asyncRoute(async (req, res) => {
  const result = await db.query(
    `SELECT id, platform, request_type, target_handle,
            quantity, status, created_at
     FROM requests
     WHERE user_id = $1
     ORDER BY id DESC`,
    [req.userId]
  );

  res.json(result.rows.map(numbers));
}));

// تسجيل طلب جديد
app.post('/api/requests', auth, asyncRoute(async (req, res) => {
  const platform = String(req.body.platform || '');
  const requestType = String(req.body.requestType || '');
  const targetHandle = String(req.body.targetHandle || '')
    .trim().replace(/^@/, '');
  const quantity = Number(req.body.quantity);

  if (!platforms.has(platform)) {
    return res.status(400).json({
      error: 'unsupported platform'
    });
  }

  if (!['followers_campaign', 'likes_campaign'].includes(requestType)) {
    return res.status(400).json({
      error: 'invalid request type'
    });
  }

  if (!/^[a-zA-Z0-9._]{2,30}$/.test(targetHandle)) {
    return res.status(400).json({
      error: 'invalid public handle'
    });
  }

  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 10000) {
    return res.status(400).json({
      error: 'quantity must be 1-10000'
    });
  }

  const result = await db.query(
    `INSERT INTO requests
     (user_id, platform, request_type, target_handle, quantity)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [req.userId, platform, requestType, targetHandle, quantity]
  );

  res.status(201).json(numbers(result.rows[0]));
}));

// لوحة مراجعة المدير
app.get('/api/admin/submissions', auth, adminOnly,
  asyncRoute(async (_req, res) => {
    const result = await db.query(`
      SELECT s.id, s.user_id, u.username,
             s.task_id, t.title, t.platform,
             t.reward, s.status, s.created_at
      FROM task_submissions s
      JOIN users u ON u.id = s.user_id
      JOIN tasks t ON t.id = s.task_id
      ORDER BY
        CASE WHEN s.status = 'pending' THEN 0 ELSE 1 END,
        s.id DESC
    `);

    res.json(result.rows.map(numbers));
  })
);

// اعتماد المهمة وصرف المكافأة داخل معاملة واحدة
app.post('/api/admin/submissions/:id/approve', auth, adminOnly,
  asyncRoute(async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({
        error: 'رقم الإرسال غير صحيح'
      });
    }

    const client = await db.connect();

    try {
      await client.query('BEGIN');

      const result = await client.query(`
        SELECT s.id, s.user_id, s.status,
               t.reward, t.title
        FROM task_submissions s
        JOIN tasks t ON t.id = s.task_id
        WHERE s.id = $1
        FOR UPDATE OF s
      `, [id]);

      const submission = result.rows[0];

      if (!submission) {
        await client.query('ROLLBACK');
        return res.status(404).json({
          error: 'المهمة المرسلة غير موجودة'
        });
      }

      if (submission.status !== 'pending') {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'تمت مراجعة هذه المهمة من قبل'
        });
      }

      const update = await client.query(
        `UPDATE task_submissions
         SET status = 'approved'
         WHERE id = $1 AND status = 'pending'
         RETURNING id`,
        [id]
      );

      if (!update.rowCount) {
        await client.query('ROLLBACK');
        return res.status(409).json({
          error: 'تمت مراجعة هذه المهمة من قبل'
        });
      }

      await client.query(
        'UPDATE users SET coins = coins + $1 WHERE id = $2',
        [submission.reward, submission.user_id]
      );

      await client.query(
        `INSERT INTO transactions (user_id, amount, reason)
         VALUES ($1, $2, $3)`,
        [
          submission.user_id,
          submission.reward,
          'مكافأة اعتماد المهمة: ' + submission.title
        ]
      );

      await client.query('COMMIT');

      res.json({
        ok: true,
        message: 'تم اعتماد المهمة وصرف النقاط',
        reward: Number(submission.reward)
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  })
);

// رفض المهمة دون صرف نقاط
app.post('/api/admin/submissions/:id/reject', auth, adminOnly,
  asyncRoute(async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({
        error: 'رقم الإرسال غير صحيح'
      });
    }

    const result = await db.query(
      `UPDATE task_submissions
       SET status = 'rejected'
       WHERE id = $1 AND status = 'pending'
       RETURNING id`,
      [id]
    );

    if (!result.rowCount) {
      return res.status(409).json({
        error: 'المهمة غير موجودة أو تمت مراجعتها بالفعل'
      });
    }

    res.json({
      ok: true,
      message: 'تم رفض المهمة بدون إضافة نقاط'
    });
  })
);

app.use(express.static('public'));

app.use((error, _req, res, _next) => {
  console.error('API ERROR:', error.message);

  if (res.headersSent) return;

  res.status(500).json({
    error: 'حدث خطأ داخلي في السيرفر'
  });
});

const port = Number(process.env.PORT || 3000);

app.listen(port, () => {
  console.log(`Kobra Follow API listening on ${port}`);
});
