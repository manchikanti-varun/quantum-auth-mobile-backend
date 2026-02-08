# QSafe Backend

Node.js + Express API for QSafe. PQC JWT (Dilithium2), Firebase Firestore, MFA challenges.

## Requirements

- Node.js 20+
- Firebase project with Firestore

## Setup

```bash
npm install
cp .env.example .env
npm run generate:pqc
```

Add generated PQC keys to `.env`. Add Firebase service account credentials from Firebase Console → Project Settings → Service Accounts.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Port (default: 4000) |
| `NODE_ENV` | No | `development` or `production` |
| `PQC_JWT_PUBLIC_KEY` | Yes | Dilithium2 public key |
| `PQC_JWT_PRIVATE_KEY` | Yes | Dilithium2 private key |
| `PQC_KYBER_PUBLIC_KEY` | Yes | ML-KEM-768 public key |
| `PQC_KYBER_PRIVATE_KEY` | Yes | ML-KEM-768 private key |
| `FIREBASE_PROJECT_ID` | Yes | Firebase project ID |
| `FIREBASE_CLIENT_EMAIL` | Yes | Service account email |
| `FIREBASE_PRIVATE_KEY` | Yes | Private key (`\n` for newlines) |
| `CORS_ORIGIN` | No | Allowed origins (comma-separated) |

## Run

```bash
npm run dev    # Development (nodemon)
npm start      # Production
```

## API

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /health` | No | Health check |
| `POST /api/auth/register` | No | Register |
| `POST /api/auth/login` | No | Login |
| `GET /api/auth/login-status` | No | Poll MFA result |
| `GET /api/auth/me` | JWT | Profile |
| `POST /api/devices/register` | JWT | Register device |
| `GET /api/mfa/pending` | JWT | Pending MFA |
| `POST /api/mfa/resolve` | JWT | Approve/deny |
| `GET /api/pqc/kyber-public-key` | No | Kyber public key |

## Deploy (Railway)

1. Connect repo
2. Add env vars (PQC keys, Firebase)
3. Deploy

Health check: `GET /health` → `{"status":"ok","firestore":true}`
