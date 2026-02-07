# QSafe Backend

Node.js + Express API for QSafe. Handles auth, device registration, MFA challenges, and TOTP backup.

---

## Setup

```bash
npm install
cp .env.example .env
```

Edit `.env` with your credentials.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PORT` | Server port (default 4000) |
| `JWT_SECRET` | Secret for signing JWTs |
| `FIREBASE_PROJECT_ID` | Firebase project ID |
| `FIREBASE_CLIENT_EMAIL` | Firebase service account email |
| `FIREBASE_PRIVATE_KEY` | Firebase private key (use `\n` for newlines) |

---

## Run

```bash
npm run dev
```

Server runs at `http://localhost:4000` (or `PORT` from `.env`).

---

## API Reference

### Auth

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register user |
| POST | `/api/auth/login` | Login (returns token or `requiresMfa` + `challengeId`) |
| GET | `/api/auth/login-status` | Poll for MFA result |
| POST | `/api/auth/login-with-otp` | Complete login with 6-digit backup code |
| GET | `/api/auth/me` | Get profile (JWT required) |
| POST | `/api/auth/change-password` | Change password (JWT required) |
| POST | `/api/auth/setup-backup-otp` | Set backup TOTP (JWT required) |
| GET | `/api/auth/login-history` | Login history (JWT required) |

### MFA

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/mfa/pending` | Get pending challenge (JWT required) |
| POST | `/api/mfa/resolve` | Approve/deny challenge (JWT + signature) |
| GET | `/api/mfa/history` | MFA history (JWT required) |

### Devices

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/devices/register` | Register device + PQC key + push token (JWT required) |

---

## Deploy to Railway

1. Create a Railway project and connect this repo.
2. Add variables in **Settings → Variables**:
   - `JWT_SECRET`
   - `FIREBASE_PROJECT_ID`
   - `FIREBASE_CLIENT_EMAIL`
   - `FIREBASE_PRIVATE_KEY` (single line with `\n` for newlines)

3. Deploy. Railway sets `PORT` automatically.

**FIREBASE_PRIVATE_KEY format** – Use a single string with `\n` (backslash-n) for line breaks, not actual newlines. Example:

```
-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANB...\n-----END PRIVATE KEY-----\n
```

---

## Health Check

```bash
curl https://your-app.up.railway.app/health
```

Expected: `{"status":"ok","service":"qsafe-backend"}`
