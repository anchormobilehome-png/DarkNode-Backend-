# DarkNode Backend

Handles account creation, email verification codes, login, and session tokens.
Passwords are hashed with bcrypt — never stored in plain text.

## What it does

- `POST /api/register` — creates an account (unverified) and emails a 6-digit code
- `POST /api/send-code` — resends a code (rate-limited, 5 per 10 min per IP)
- `POST /api/verify-email` — checks the code, marks the account verified, returns a session token
- `POST /api/login` — checks email/password; if the account isn't verified yet, sends a fresh code instead of logging in
- `GET /api/me` — returns the logged-in user (requires the token)
- `POST /api/subscription/activate` — flips a user to subscribed for 30 days (call this *after* you've verified a Flutterwave payment server-side — see note below)

## 1. Install

```bash
npm install
cp .env.example .env
```

Fill in `.env`:
- `JWT_SECRET` — generate one with:
  ```bash
  node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
  ```
- `ALLOWED_ORIGINS` — your frontend's URL(s), comma-separated
- `SMTP_*` — your email provider's credentials. Easiest options if you don't already have one:
  - **Resend** (resend.com) — generous free tier, simple SMTP
  - **SendGrid** — also has a free tier
  - Gmail works for testing but needs an "App Password," not your normal password, and has low sending limits

## 2. Run locally

```bash
npm start
```

Server runs on `http://localhost:4000` (or whatever `PORT` you set).

## 3. Deploy

Any Node host works. Easiest for a small project:
- **Render** (render.com) — free tier, connect your GitHub repo, set the env vars in their dashboard
- **Railway** (railway.app) — similar, very quick to deploy

The SQLite file (`darknode.db`) lives on disk next to the server. On Render/Railway's free tiers, disk can reset on redeploy — fine for testing, but for real users move to a hosted Postgres (Render and Railway both offer one) once you're past prototyping. The queries would need light changes (`better-sqlite3` → `pg`), happy to help with that migration when you're ready.

## 4. Connect the frontend

The frontend (`darknode.html`) is already wired up to call this API — you just need to:

1. Open `darknode.html` and find this line near the top of the `<script>` block:
   ```js
   const API_BASE = "https://YOUR-BACKEND-URL.example.com";
   ```
   Replace it with your deployed backend's URL (e.g. from Render/Railway).
2. Deploy this backend somewhere reachable (step 3 above) and add that URL to `ALLOWED_ORIGINS` in your backend `.env` so CORS allows requests from wherever `darknode.html` is hosted.

The flow it now runs: register → 6-digit email code screen → verify → dashboard.
Login checks the same way — if an account isn't verified yet, it automatically
sends a new code and drops the user onto the verify screen instead of logging
them in.

## 5. Payment verification (already wired up)

`POST /api/subscription/activate` now verifies the transaction with Flutterwave's
`GET /v3/transactions/:id/verify` endpoint using your **secret key**, and only
marks the user subscribed if the payment is confirmed successful, in NGN, and
at least ₦5,000. Add your real secret key to `.env` as `FLUTTERWAVE_SECRET_KEY`
(from your Flutterwave dashboard — never put this in frontend code).

The frontend calls this route with the `transaction_id` and `tx_ref` it gets
back from Flutterwave's checkout modal after a successful charge.
