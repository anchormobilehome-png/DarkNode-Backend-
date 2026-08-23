require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();

// Render (and most hosts) sit behind a proxy, so the app needs to trust the
// first proxy hop to correctly read the real visitor IP. Without this,
// express-rate-limit throws an error on every request.
app.set('trust proxy', 1);
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('Missing JWT_SECRET in .env — refusing to start.');
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error('Missing DATABASE_URL in .env — refusing to start.');
  process.exit(1);
}

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
      cb(new Error('Not allowed by CORS'));
    },
  })
);
app.use(express.json());

// ---------- Database (PostgreSQL — a real, permanent database) ----------
// Unlike the old SQLite file, this data survives every redeploy.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // needed for Render-hosted Postgres
  max: 10,                      // max simultaneous connections
  idleTimeoutMillis: 30000,     // release unused connections after 30s
  connectionTimeoutMillis: 8000, // give up trying to connect after 8s instead of hanging
});

// CRITICAL: without this handler, a dropped/idle database connection
// (which happens more often under real traffic) crashes the ENTIRE
// server — this is a Node.js/pg gotcha, not something obvious. This
// alone could explain a server going down right as ad traffic hit.
pool.on('error', (err) => {
  console.error('Unexpected database pool error (recovered, not crashing):', err.message);
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email_verified BOOLEAN NOT NULL DEFAULT FALSE,
      subscribed BOOLEAN NOT NULL DEFAULT FALSE,
      subscription_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS verification_codes (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      purpose TEXT NOT NULL DEFAULT 'email_verification',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE verification_codes ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'email_verification';

    CREATE TABLE IF NOT EXISTS scheduled_posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      platform TEXT NOT NULL,
      caption TEXT NOT NULL,
      scheduled_at TIMESTAMPTZ NOT NULL,
      status TEXT NOT NULL DEFAULT 'scheduled',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

// ---------- Email (via Brevo's HTTP API) ----------
// NOTE: We use Brevo's REST API instead of SMTP because Render's free tier
// blocks all outbound SMTP ports (25, 465, 587) as an anti-spam measure —
// this is a platform-level block, not something fixable with SMTP settings.
// Brevo sends over regular HTTPS (port 443), which isn't blocked.
async function sendEmail({ to, subject, text, html }) {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.BREVO_SENDER_EMAIL;
  if (!apiKey || !senderEmail) {
    throw new Error('Email is not configured (missing BREVO_API_KEY or BREVO_SENDER_EMAIL).');
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': apiKey,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        sender: { email: senderEmail, name: 'DarkNode' },
        to: [{ email: to }],
        subject,
        textContent: text,
        htmlContent: html,
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`Brevo send failed (${res.status}): ${body}`);
    }
  } finally {
    clearTimeout(timeout);
  }
}

async function sendVerificationEmail(email, code) {
  await sendEmail({
    to: email,
    subject: 'Your DarkNode verification code',
    text: `Your DarkNode verification code is ${code}. It expires in 10 minutes. If you didn't request this, ignore this email.`,
    html: `<p>Your DarkNode verification code is:</p>
           <p style="font-size:28px;font-weight:700;letter-spacing:4px;">${code}</p>
           <p>It expires in 10 minutes. If you didn't request this, you can ignore this email.</p>`,
  });
}

async function sendPasswordResetEmail(email, code) {
  await sendEmail({
    to: email,
    subject: 'Reset your DarkNode password',
    text: `Your DarkNode password reset code is ${code}. It expires in 10 minutes. If you didn't request this, you can safely ignore this email — your password will not be changed.`,
    html: `<p>Your DarkNode password reset code is:</p>
           <p style="font-size:28px;font-weight:700;letter-spacing:4px;">${code}</p>
           <p>It expires in 10 minutes. If you didn't request this, you can safely ignore this email — your password will not be changed.</p>`,
  });
}

function generateCode() {
  // 6-digit numeric code, e.g. 042911
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

// ---------- Rate limiting ----------
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 150, // generous — many real customers share one IP via mobile carrier NAT
  standardHeaders: true,
  legacyHeaders: false,
});
const codeLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 5, // max 5 code requests per 10 min per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many code requests. Wait a bit and try again.' },
});
app.use('/api/', authLimiter);

// ---------- Helpers ----------
function signToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session.' });
  }
}

// A user only counts as actively subscribed if the "subscribed" flag is set
// AND their subscription hasn't passed its expiry date. This is checked
// fresh every time (not just once at payment) so access actually turns off
// automatically 30 days after payment, instead of staying unlocked forever.
function isSubscriptionActive(row) {
  if (!row.subscribed) return false;
  if (!row.subscription_expires_at) return false;
  return new Date(row.subscription_expires_at).getTime() > Date.now();
}

function publicUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    emailVerified: !!row.email_verified,
    subscribed: isSubscriptionActive(row),
    subscriptionExpiresAt: row.subscription_expires_at,
  };
}

// Wraps a route handler so any thrown/rejected error is caught and sent
// back as a normal error response, instead of crashing the whole server.
function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// =====================================================
// POST /api/register
// Creates the account and logs the user straight in.
// (Email verification is currently skipped — see note below.)
// =====================================================
app.post('/api/register', asyncHandler(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email and password are required.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  if (existing.rows.length > 0) {
    return res.status(409).json({ error: 'An account with that email already exists.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  // NOTE: email_verified is set to TRUE immediately — email code verification
  // is skipped for now since SMTP/email sending isn't fully set up yet.
  // To turn verification back on later: change TRUE to FALSE below, and
  // change handleRegister() in darknode.html to show the verify-code screen
  // again instead of logging the user straight in.
  const result = await pool.query(
    `INSERT INTO users (name, email, password_hash, email_verified)
     VALUES ($1, $2, $3, TRUE)
     RETURNING *`,
    [name, email, passwordHash]
  );

  const user = result.rows[0];
  const token = signToken(user);
  res.status(201).json({ token, user: publicUser(user) });
}));

// =====================================================
// POST /api/send-code
// (Re)sends a verification code to an email — used for
// resend, or for login-time verification if not yet verified.
// =====================================================
app.post('/api/send-code', codeLimiter, asyncHandler(async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email is required.' });

  const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  if (existing.rows.length === 0) {
    // Don't reveal whether the email exists.
    return res.json({ message: 'If that account exists, a code has been sent.' });
  }

  // Respond right away instead of waiting on the email itself.
  res.json({ message: 'If that account exists, a code has been sent.' });
  issueAndSendCode(email).catch((err) => {
    console.error('Failed to send verification email:', err.message);
  });
}));

async function issueAndSendCode(email, purpose = 'email_verification') {
  const code = generateCode();
  const codeHash = await bcrypt.hash(code, 10);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  await pool.query('DELETE FROM verification_codes WHERE email = $1 AND purpose = $2', [email, purpose]);
  await pool.query(
    'INSERT INTO verification_codes (email, code_hash, expires_at, purpose) VALUES ($1, $2, $3, $4)',
    [email, codeHash, expiresAt, purpose]
  );

  if (purpose === 'password_reset') {
    await sendPasswordResetEmail(email, code);
  } else {
    await sendVerificationEmail(email, code);
  }
}

// =====================================================
// POST /api/forgot-password
// Body: { email }
// Always responds the same way whether or not the email exists,
// so people can't use this to check which emails are registered.
// =====================================================
app.post('/api/forgot-password', codeLimiter, asyncHandler(async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email is required.' });

  const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);

  // Respond right away — don't make the user wait on the email itself,
  // which can be slow or hang if SMTP settings have an issue.
  res.json({ message: 'If that account exists, a reset code has been sent.' });

  if (existing.rows.length > 0) {
    issueAndSendCode(email, 'password_reset').catch((err) => {
      console.error('Failed to send password reset email:', err.message);
    });
  }
}));

// =====================================================
// POST /api/reset-password
// Body: { email, code, newPassword }
// =====================================================
app.post('/api/reset-password', asyncHandler(async (req, res) => {
  const { email, code, newPassword } = req.body || {};
  if (!email || !code || !newPassword) {
    return res.status(400).json({ error: 'Email, code and new password are required.' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const result = await pool.query(
    'SELECT * FROM verification_codes WHERE email = $1 AND purpose = $2',
    [email, 'password_reset']
  );
  const row = result.rows[0];
  if (!row) return res.status(400).json({ error: 'No pending reset code for this email. Request a new one.' });

  if (new Date(row.expires_at).getTime() < Date.now()) {
    await pool.query('DELETE FROM verification_codes WHERE id = $1', [row.id]);
    return res.status(400).json({ error: 'Code expired. Request a new one.' });
  }
  if (row.attempts >= 5) {
    await pool.query('DELETE FROM verification_codes WHERE id = $1', [row.id]);
    return res.status(429).json({ error: 'Too many incorrect attempts. Request a new code.' });
  }

  const match = await bcrypt.compare(code, row.code_hash);
  if (!match) {
    await pool.query('UPDATE verification_codes SET attempts = attempts + 1 WHERE id = $1', [row.id]);
    return res.status(400).json({ error: 'Incorrect code.' });
  }

  const passwordHash = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [passwordHash, email]);
  await pool.query('DELETE FROM verification_codes WHERE id = $1', [row.id]);

  res.json({ message: 'Password updated. You can now log in with your new password.' });
}));

// =====================================================
// POST /api/verify-email
// Body: { email, code }
// =====================================================
app.post('/api/verify-email', asyncHandler(async (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !code) return res.status(400).json({ error: 'Email and code are required.' });

  const result = await pool.query(
    'SELECT * FROM verification_codes WHERE email = $1 AND purpose = $2',
    [email, 'email_verification']
  );
  const row = result.rows[0];
  if (!row) return res.status(400).json({ error: 'No pending code for this email. Request a new one.' });

  if (new Date(row.expires_at).getTime() < Date.now()) {
    await pool.query('DELETE FROM verification_codes WHERE id = $1', [row.id]);
    return res.status(400).json({ error: 'Code expired. Request a new one.' });
  }

  if (row.attempts >= 5) {
    await pool.query('DELETE FROM verification_codes WHERE id = $1', [row.id]);
    return res.status(429).json({ error: 'Too many incorrect attempts. Request a new code.' });
  }

  const match = await bcrypt.compare(code, row.code_hash);
  if (!match) {
    await pool.query('UPDATE verification_codes SET attempts = attempts + 1 WHERE id = $1', [row.id]);
    return res.status(400).json({ error: 'Incorrect code.' });
  }

  await pool.query('UPDATE users SET email_verified = TRUE WHERE email = $1', [email]);
  await pool.query('DELETE FROM verification_codes WHERE id = $1', [row.id]);

  const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = userResult.rows[0];
  const token = signToken(user);
  res.json({ token, user: publicUser(user) });
}));

// =====================================================
// POST /api/login
// =====================================================
app.post('/api/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: 'Incorrect email or password.' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Incorrect email or password.' });

  // Email verification check skipped for now — see note in /api/register.
  const token = signToken(user);
  res.json({ token, user: publicUser(user) });
}));

// =====================================================
// GET /api/me  (requires Bearer token)
// =====================================================
app.get('/api/me', authMiddleware, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.sub]);
  const user = result.rows[0];
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json({ user: publicUser(user) });
}));

// =====================================================
// POST /api/subscription/activate
// Body: { reference }
// Verifies the payment with Paystack's API (server-side,
// using the secret key) before marking the account subscribed.
// This does NOT trust the frontend callback alone.
// =====================================================
app.post('/api/subscription/activate', authMiddleware, asyncHandler(async (req, res) => {
  const { reference } = req.body || {};
  if (!reference) {
    return res.status(400).json({ error: 'Missing reference.' });
  }

  try {
    const verifyRes = await fetch(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      }
    );
    const verifyData = await verifyRes.json();

    const tx = verifyData && verifyData.data;
    const ok =
      verifyData.status === true &&
      tx &&
      tx.status === 'success' &&
      tx.currency === 'NGN' &&
      tx.amount >= 500000; // kobo

    if (!ok) {
      return res.status(402).json({ error: 'Payment could not be verified.' });
    }

    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    await pool.query(
      'UPDATE users SET subscribed = TRUE, subscription_expires_at = $1 WHERE id = $2',
      [expires, req.user.sub]
    );

    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.sub]);
    res.json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error('Paystack verify error:', err);
    res.status(502).json({ error: 'Could not reach payment verification service.' });
  }
}));

// =====================================================
// CONTENT SCHEDULING
// Only subscribed users can use these — checked via
// requireSubscription below.
// =====================================================
async function requireSubscription(req, res, next) {
  const result = await pool.query(
    'SELECT subscribed, subscription_expires_at FROM users WHERE id = $1',
    [req.user.sub]
  );
  const user = result.rows[0];
  if (!user || !isSubscriptionActive(user)) {
    return res.status(403).json({ error: 'An active subscription is required.' });
  }
  next();
}

function publicPost(row) {
  return {
    id: row.id,
    platform: row.platform,
    caption: row.caption,
    scheduledAt: row.scheduled_at,
    status: row.status,
    createdAt: row.created_at,
  };
}

// GET /api/posts?platform=instagram
// Lists the logged-in user's scheduled posts, optionally filtered by platform.
app.get('/api/posts', authMiddleware, requireSubscription, asyncHandler(async (req, res) => {
  const { platform } = req.query;
  let result;
  if (platform) {
    result = await pool.query(
      'SELECT * FROM scheduled_posts WHERE user_id = $1 AND platform = $2 ORDER BY scheduled_at ASC',
      [req.user.sub, platform]
    );
  } else {
    result = await pool.query(
      'SELECT * FROM scheduled_posts WHERE user_id = $1 ORDER BY scheduled_at ASC',
      [req.user.sub]
    );
  }
  res.json({ posts: result.rows.map(publicPost) });
}));

// POST /api/posts
// Body: { platform, caption, scheduledAt, status } — status defaults to 'scheduled', can be 'draft'
app.post('/api/posts', authMiddleware, requireSubscription, asyncHandler(async (req, res) => {
  const { platform, caption, scheduledAt, status } = req.body || {};
  if (!platform || !caption || !scheduledAt) {
    return res.status(400).json({ error: 'platform, caption and scheduledAt are required.' });
  }
  if (caption.length > 2000) {
    return res.status(400).json({ error: 'Caption is too long (max 2000 characters).' });
  }
  const when = new Date(scheduledAt);
  if (isNaN(when.getTime())) {
    return res.status(400).json({ error: 'scheduledAt must be a valid date/time.' });
  }
  const safeStatus = status === 'draft' ? 'draft' : 'scheduled';

  const result = await pool.query(
    `INSERT INTO scheduled_posts (user_id, platform, caption, scheduled_at, status)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [req.user.sub, platform, caption, when.toISOString(), safeStatus]
  );
  res.status(201).json({ post: publicPost(result.rows[0]) });
}));

// PATCH /api/posts/:id
// Body: any of { caption, scheduledAt, status } — updates only what's provided.
// Used for both editing a post and toggling draft <-> scheduled.
app.patch('/api/posts/:id', authMiddleware, requireSubscription, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { caption, scheduledAt, status } = req.body || {};

  const existing = await pool.query(
    'SELECT * FROM scheduled_posts WHERE id = $1 AND user_id = $2',
    [id, req.user.sub]
  );
  if (existing.rows.length === 0) {
    return res.status(404).json({ error: 'Post not found.' });
  }

  const current = existing.rows[0];
  const newCaption = caption !== undefined ? caption : current.caption;
  const newScheduledAt = scheduledAt !== undefined ? new Date(scheduledAt) : new Date(current.scheduled_at);
  const newStatus = status !== undefined ? status : current.status;

  if (newCaption.length > 2000) {
    return res.status(400).json({ error: 'Caption is too long (max 2000 characters).' });
  }
  if (isNaN(newScheduledAt.getTime())) {
    return res.status(400).json({ error: 'scheduledAt must be a valid date/time.' });
  }
  if (!['draft', 'scheduled', 'published', 'failed'].includes(newStatus)) {
    return res.status(400).json({ error: 'Invalid status.' });
  }

  const result = await pool.query(
    `UPDATE scheduled_posts SET caption = $1, scheduled_at = $2, status = $3
     WHERE id = $4 AND user_id = $5
     RETURNING *`,
    [newCaption, newScheduledAt.toISOString(), newStatus, id, req.user.sub]
  );
  res.json({ post: publicPost(result.rows[0]) });
}));

// DELETE /api/posts/:id
app.delete('/api/posts/:id', authMiddleware, requireSubscription, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const result = await pool.query(
    'DELETE FROM scheduled_posts WHERE id = $1 AND user_id = $2 RETURNING id',
    [id, req.user.sub]
  );
  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Post not found.' });
  }
  res.json({ deleted: true });
}));

// =====================================================
// POST /api/generate-caption
// Body: { platform, topic }
// Uses Google's free Gemini API to generate caption + hashtag ideas.
// Requires an active subscription, same as scheduling.
// =====================================================
app.post('/api/generate-caption', authMiddleware, requireSubscription, asyncHandler(async (req, res) => {
  const { platform, topic } = req.body || {};
  if (!topic || !topic.trim()) {
    return res.status(400).json({ error: 'Describe what the post is about first.' });
  }
  if (topic.length > 300) {
    return res.status(400).json({ error: 'Keep the description under 300 characters.' });
  }
  if (!process.env.GEMINI_API_KEY) {
    return res.status(503).json({ error: 'AI captions are not configured yet.' });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const prompt = `You write short social media captions for ${platform || 'social media'}. Write captions for a post about: ${topic.trim()}

Respond with ONLY valid JSON, no other text, in this exact shape:
{"captions":[{"style":"Professional","text":"...","hashtags":["#tag1","#tag2"],"cta":"..."},{"style":"Engaging","text":"...","hashtags":["#tag1","#tag2"],"cta":"..."},{"style":"Short & direct","text":"...","hashtags":["#tag1","#tag2"],"cta":"..."}]}

Give exactly those 3 caption options in that order. "Professional" is polished and businesslike. "Engaging" is warm, conversational, inviting interaction. "Short & direct" is brief and to the point. Each caption text should be 1-3 sentences (shorter for "Short & direct"), no hashtags inside the text itself. 3-5 relevant hashtags per option. "cta" is a short call-to-action phrase (e.g. "Book now", "DM to order", "Tap the link in bio") relevant to the topic.`;

    const geminiRes = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.8,
            maxOutputTokens: 600,
            responseMimeType: 'application/json',
          },
        }),
        signal: controller.signal,
      }
    );

    if (!geminiRes.ok) {
      const body = await geminiRes.text().catch(() => '');
      console.error('Gemini API error:', geminiRes.status, body);
      return res.status(502).json({ error: 'Could not generate captions right now. Try again shortly.' });
    }

    const data = await geminiRes.json();
    const raw = data.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return res.status(502).json({ error: 'Got an unexpected response. Try again.' });
    }

    res.json({ captions: parsed.captions || [] });
  } catch (err) {
    if (err.name === 'AbortError') {
      return res.status(504).json({ error: 'That took too long. Try again.' });
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}));

// =====================================================
// POST /api/social/:platform/connect
// Honest placeholder — DarkNode does not yet have official
// developer approval from any of these platforms, so this can
// never claim a real connection succeeded. It's here so the
// frontend has a real endpoint to call, and returns a clear,
// accurate message instead of faking a successful connection.
// When real OAuth credentials for a platform are set up, replace
// this platform's branch with the actual authorization redirect.
// =====================================================
app.post('/api/social/:platform/connect', authMiddleware, requireSubscription, asyncHandler(async (req, res) => {
  const { platform } = req.params;
  const known = ['instagram', 'facebook', 'snapchat', 'tiktok'];
  if (!known.includes(platform)) {
    return res.status(404).json({ error: 'Unknown platform.' });
  }
  res.status(501).json({
    error: `Official account connection for ${platform} isn't set up yet — this requires developer approval from the platform, which DarkNode hasn't completed.`,
    notImplemented: true,
  });
}));

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Catch-all error handler — makes sure a broken request sends back a normal
// error response instead of crashing the whole server.
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

// Extra safety net: log unexpected crashes instead of letting the whole
// process die silently.
process.on('unhandledRejection', (err) => {
  console.error('Unhandled promise rejection:', err);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`DarkNode backend listening on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to set up database:', err);
    process.exit(1);
  });
