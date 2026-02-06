# QSafe Backend

Node.js + Express API for QSafe. Handles auth, device registration, MFA challenges, and TOTP backup.

## Setup

```bash
npm install
cp .env.example .env
# Edit .env with your Firebase and JWT_SECRET
```

## Run

```bash
npm run dev
```

## Env vars (see .env.example)

- `PORT` – server port (default 4000)
- `JWT_SECRET` – secret for signing JWTs
- `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`, `FIREBASE_PRIVATE_KEY` – Firebase Admin SDK

## API overview

- `POST /api/auth/register` – register user
- `POST /api/auth/login` – login (returns token or `requiresMfa` + `challengeId`)
- `GET /api/auth/login-status` – poll for MFA result (new device)
- `POST /api/auth/login-with-otp` – complete login with 6-digit backup code
- `POST /api/auth/setup-backup-otp` – set backup TOTP (JWT required)
- `GET /api/mfa/pending` – get pending MFA challenge (JWT required)
- `POST /api/mfa/resolve` – approve/deny challenge (JWT + PQC signature)
- `POST /api/devices/register` – register device + PQC public key + push token (JWT required)
