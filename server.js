require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('Missing JWT_SECRET in .env — refusing to start.');
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

// ---------- Database ----------
const db = new Database(path.join(__dirname, 'darknode.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    subscribed INTEGER NOT NULL DEFAULT 0,
    subscription_expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS verification_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// ---------- Email ----------
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false, // true for port 465
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendVerificationEmail(email, code) {
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: email,
    subject: 'Your DarkNode verification code',
    text: `Your DarkNode verification code is ${code}. It expires in 10 minutes. If you didn't request this, ignore this email.`,
    html: `<p>Your DarkNode verification code is:</p>
           <p style="font-size:28px;font-weight:700;letter-spacing:4px;">${code}</p>
           <p>It expires in 10 minutes. If you didn't request this, you can ignore this email.</p>`,
  });
}

function generateCode() {
  // 6-digit numeric code, e.g. 042911
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

// ---------- Rate limiting ----------
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
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

function publicUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    emailVerified: !!row.email_verified,
    subscribed: !!row.subscribed,
    subscriptionExpiresAt: row.subscription_expires_at,
  };
}

// =====================================================
// POST /api/register
// Creates the account (unverified) and emails a code.
// =====================================================
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email and password are required.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    return res.status(409).json({ error: 'An account with that email already exists.' });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  // NOTE: email_verified is set to 1 immediately — email code verification
  // is skipped for now since SMTP/email sending isn't fully set up yet.
  // To turn verification back on later: change this back to 0, and change
  // handleRegister() in darknode.html to show the verify-code screen again
  // instead of logging the user straight in.
  const insert = db.prepare(
    'INSERT INTO users (name, email, password_hash, email_verified) VALUES (?, ?, ?, 1)'
  );
  const result = insert.run(name, email, passwordHash);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
  const token = signToken(user);
  res.status(201).json({ token, user: publicUser(user) });
});

// =====================================================
// POST /api/send-code
// (Re)sends a verification code to an email — used for
// resend, or for login-time verification if not yet verified.
// =====================================================
app.post('/api/send-code', codeLimiter, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email is required.' });

  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!user) {
    // Don't reveal whether the email exists.
    return res.json({ message: 'If that account exists, a code has been sent.' });
  }

  try {
    await issueAndSendCode(email);
  } catch (err) {
    console.error('Failed to send verification email:', err.message);
    return res.status(502).json({ error: 'Could not send the email right now. Try again shortly.' });
  }
  res.json({ message: 'If that account exists, a code has been sent.' });
});

async function issueAndSendCode(email) {
  const code = generateCode();
  const codeHash = await bcrypt.hash(code, 10);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  db.prepare('DELETE FROM verification_codes WHERE email = ?').run(email);
  db.prepare(
    'INSERT INTO verification_codes (email, code_hash, expires_at) VALUES (?, ?, ?)'
  ).run(email, codeHash, expiresAt);

  await sendVerificationEmail(email, code);
}

// =====================================================
// POST /api/verify-email
// Body: { email, code }
// =====================================================
app.post('/api/verify-email', async (req, res) => {
  const { email, code } = req.body || {};
  if (!email || !code) return res.status(400).json({ error: 'Email and code are required.' });

  const row = db.prepare('SELECT * FROM verification_codes WHERE email = ?').get(email);
  if (!row) return res.status(400).json({ error: 'No pending code for this email. Request a new one.' });

  if (new Date(row.expires_at).getTime() < Date.now()) {
    db.prepare('DELETE FROM verification_codes WHERE email = ?').run(email);
    return res.status(400).json({ error: 'Code expired. Request a new one.' });
  }

  if (row.attempts >= 5) {
    db.prepare('DELETE FROM verification_codes WHERE email = ?').run(email);
    return res.status(429).json({ error: 'Too many incorrect attempts. Request a new code.' });
  }

  const match = await bcrypt.compare(code, row.code_hash);
  if (!match) {
    db.prepare('UPDATE verification_codes SET attempts = attempts + 1 WHERE email = ?').run(email);
    return res.status(400).json({ error: 'Incorrect code.' });
  }

  db.prepare('UPDATE users SET email_verified = 1 WHERE email = ?').run(email);
  db.prepare('DELETE FROM verification_codes WHERE email = ?').run(email);

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  const token = signToken(user);
  res.json({ token, user: publicUser(user) });
});

// =====================================================
// POST /api/login
// =====================================================
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'Incorrect email or password.' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Incorrect email or password.' });

  // Email verification check skipped for now — see note in /api/register.
  const token = signToken(user);
  res.json({ token, user: publicUser(user) });
});

// =====================================================
// GET /api/me  (requires Bearer token)
// =====================================================
app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json({ user: publicUser(user) });
});

// =====================================================
// POST /api/subscription/activate
// Body: { reference }
// Verifies the payment with Paystack's API (server-side,
// using the secret key) before marking the account subscribed.
// This does NOT trust the frontend callback alone.
// =====================================================
app.post('/api/subscription/activate', authMiddleware, async (req, res) => {
  const { reference } = req.body || {};
  if (!reference) {
    return res.status(400).json({ error: 'Missing reference.' });
  }

  try{
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
    db.prepare(
      'UPDATE users SET subscribed = 1, subscription_expires_at = ? WHERE id = ?'
    ).run(expires, req.user.sub);

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
    res.json({ user: publicUser(user) });
  }catch(err){
    console.error('Paystack verify error:', err);
    res.status(502).json({ error: 'Could not reach payment verification service.' });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Catch-all error handler — makes sure a broken request sends back a normal
// error response instead of crashing the whole server.
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

// Extra safety net: log unexpected crashes instead of letting the whole
// process die silently. (This doesn't fix the underlying bug — it just
// keeps the server running so one bad request can't take everyone down.)
process.on('unhandledRejection', (err) => {
  console.error('Unhandled promise rejection:', err);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
});

app.listen(PORT, () => {
  console.log(`DarkNode backend listening on port ${PORT}`);
});
