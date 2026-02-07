# QSafe Backend

Node.js + Express API for QSafe – quantum-safe authenticator. Handles auth, device registration, MFA challenges, and TOTP backup.

## Features

- **Auth**: Register, login, JWT tokens
- **MFA**: Approve/deny login on another device (PQC signatures)
- **TOTP**: Provision QR codes for authenticator apps
- **Devices**: Register devices with PQC keys, push notifications
- **Production**: Helmet, rate limiting, env validation, CORS

---

## Setup

```bash
npm install
cp .env.example .env
```

Edit `.env` with your credentials.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Server port (default: 4000) |
| `NODE_ENV` | No | `development` or `production` |
| `JWT_SECRET` | Yes | Secret for signing JWTs (32+ chars in production) |
| `FIREBASE_PROJECT_ID` | Yes | Firebase project ID |
| `FIREBASE_CLIENT_EMAIL` | Yes | Firebase service account email |
| `FIREBASE_PRIVATE_KEY` | Yes | Firebase private key (use `\n` for newlines) |
| `CORS_ORIGIN` | No | Comma-separated allowed origins |

---

## Run

**Development:** `NODE_ENV=development npm run dev`  
**Production:** `npm start`

Server runs at `http://localhost:4000` (or `PORT` from `.env`).

---

## API Reference

### Auth

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | No | Register user |
| POST | `/api/auth/login` | No | Login |
| GET | `/api/auth/login-status` | No | Poll for MFA result |
| POST | `/api/auth/login-with-otp` | No | Complete login with 6-digit backup code |
| GET | `/api/auth/me` | JWT | Get profile |
| POST | `/api/auth/change-password` | JWT | Change password |
| POST | `/api/auth/setup-backup-otp` | JWT | Set backup TOTP |
| GET | `/api/auth/login-history` | JWT | Login history |

### TOTP

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/totp/provision` | JWT | Generate TOTP QR |

### MFA

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/mfa/pending` | JWT | Get pending challenge |
| POST | `/api/mfa/resolve` | JWT | Approve/deny (PQC signature) |
| POST | `/api/mfa/generate-code` | JWT | Generate one-time code |
| GET | `/api/mfa/history` | JWT | MFA history |

### Devices

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/devices/register` | JWT | Register device + PQC key + push token |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |

---

## Deploy to Railway

1. Create a Railway project and connect this repo.
2. Add variables in **Settings → Variables**:
   - `NODE_ENV` = `production`
   - `JWT_SECRET` (strong, 32+ chars)
   - `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`, `FIREBASE_PRIVATE_KEY`
   - `CORS_ORIGIN` (optional)

3. Deploy. Railway sets `PORT` automatically.

**FIREBASE_PRIVATE_KEY format** – Single string with `\n` for line breaks:

```
-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANB...\n-----END PRIVATE KEY-----\n
```

---

## Production Checklist

- [ ] `NODE_ENV=production`
- [ ] Strong `JWT_SECRET` (32+ chars)
- [ ] Firebase credentials set
- [ ] `CORS_ORIGIN` set (optional)

**Health check:** `curl https://your-app.up.railway.app/health`  
Expected: `{"status":"ok","service":"qsafe-backend","firestore":true}`
