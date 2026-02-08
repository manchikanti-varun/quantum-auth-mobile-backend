# QSafe Backend – Codebase Documentation

Production-ready documentation for the QSafe 2FA authenticator backend API.

---

## Entry Point

### `index.js`
Express server entry point. Configures CORS, helmet, rate limiting. Production: validates JWT_SECRET and required env vars on startup. Mounts auth, TOTP, devices, MFA routes. Schedules duplicate device cleanup on startup and every 24 hours. Health check at `/health`.

---

## Routes

### `authRoutes.js`
Auth API routes. POST `/register`, `/login`, `/login-with-otp`. GET `/login-status` (MFA poll), `/login-history`, `/me`, `/check-recovery-options`. PATCH `/preferences`. POST `/change-password`, `/forgot-password`, `/forgot-password-security-code`, `/request-password-reset-code`, `/setup-backup-otp`. DELETE `/login-history/:id`.

### `authController.js`
Auth controller logic. Register, login, MFA challenge creation, backup OTP, password reset (device code, security code), preferences, login history. Uses bcrypt, JWT, Firestore, Expo push.

### `authMiddleware.js`
JWT verification middleware. Attaches `req.user` (uid, email). Rejects weak JWT_SECRET in production.

### `deviceRoutes.js`
Device API routes. GET `/` (list devices). POST `/register` (deviceId, pqcPublicKey, pqcAlgorithm, pushToken), `/revoke`.

### `mfaRoutes.js`
MFA API routes. GET `/pending` (poll for Device 1 only), `/history`. POST `/resolve` (approve/deny with PQC signature), `/generate-code` (backup OTP for Device 2).

### `totpRoutes.js`
TOTP provisioning. POST `/provision` (issuer, accountName, optional secret). Returns otpauth URI and QR data URL.

---

## Services

### `services/deviceCleanup.js`
Removes duplicate device documents (same uid+deviceId). Keeps most recent per key. Runs on startup and every 24 hours.

---

## Infrastructure

### `firebase.js`
Firebase Admin SDK initialization. Firestore for users, devices, MFA challenges. Handles Railway env (quoted FIREBASE_PRIVATE_KEY with escaped newlines). Exports `admin`, `db`.

---

## Validation & Constants

### `validation.js`
Auth validation. `isValidEmail`, `validatePassword`, `validateRegister`, `validateLogin`, `validateSecurityCode`. Matches mobile validation rules.

### `constants/securityQuestions.js`
Security question options for account recovery. Must match mobile constants. Exports `SECURITY_QUESTIONS`, `getQuestionById`, `normalizeAnswer`.

---

## Scripts

### `scripts/cleanup-duplicate-devices.js`
CLI script to run duplicate device cleanup. `node scripts/cleanup-duplicate-devices.js`.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| JWT_SECRET | Yes | 32+ chars, no weak values |
| FIREBASE_PROJECT_ID | Yes | Firebase project ID |
| FIREBASE_CLIENT_EMAIL | Yes | Firebase service account email |
| FIREBASE_PRIVATE_KEY | Yes | Firebase private key (Railway: quoted, `\n` escaped) |
| PORT | No | Server port (default 4000) |
| CORS_ORIGIN | No | Comma-separated origins |
