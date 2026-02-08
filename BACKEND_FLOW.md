# QSafe Backend – Complete Flow (Detailed)

This document explains the full backend flow: authentication, JWT creation/verification, MFA, device registration, and data storage.

---

## 1. Architecture Overview

```
┌─────────────────┐     HTTP/JSON      ┌──────────────────────────┐
│  Mobile App     │ ◄────────────────► │  Express Backend          │
│  (React Native) │                    │  - authRoutes             │
└─────────────────┘                    │  - authController         │
        │                              │  - authMiddleware         │
        │                              │  - deviceRoutes           │
        │                              │  - mfaRoutes              │
        │                              └────────────┬─────────────┘
        │                                           │
        │                              ┌────────────▼─────────────┐
        │                              │  Firestore (Firebase)    │
        │                              │  - users                 │
        │                              │  - devices               │
        │                              │  - mfaChallenges         │
        │                              │  - loginHistory          │
        │                              │  - mfaHistory            │
        │                              │  - revokedDevices        │
        │                              └─────────────────────────┘
```

---

## 2. JWT Creation & Verification

### Where JWT is CREATED (`signJwt` in authController.js)

The function `signJwt(payload)` creates a JWT:

```javascript
// authController.js, line 65-71
function signJwt(payload) {
  const secret = process.env.JWT_SECRET;
  return jwt.sign(payload, secret, { expiresIn: '1h' });
}
```

**Payload:** `{ uid, email }` – user ID from Firestore and email.

**JWT is created in these places:**

| Location | When | Payload |
|----------|------|---------|
| `register` (line 179) | After successful registration | `{ uid: createdRef.id, email }` |
| `login` (line 239) | First-time login (no devices yet) | `{ uid, email }` |
| `login` (line 263) | Trusted device (remember_device) | `{ uid, email }` |
| `getLoginStatus` (line 401) | Poll returns "approved" | `{ uid, email }` |
| `loginWithOtp` (line 391) | Backup OTP completes login | `{ uid, email }` |

### Where JWT is VERIFIED (`authMiddleware.js`)

```javascript
// authMiddleware.js
const token = authHeader.slice(7);  // Remove "Bearer "
const decoded = jwt.verify(token, secret);
req.user = { uid: decoded.uid, email: decoded.email };
next();
```

**Protected routes** (require `Authorization: Bearer <token>`):

- `POST /api/auth/setup-backup-otp`
- `GET /api/auth/login-history`
- `DELETE /api/auth/login-history/:id`
- `GET /api/auth/me`
- `POST /api/auth/change-password`
- `POST /api/devices/register`
- `POST /api/devices/revoke`
- `GET /api/mfa/pending`
- `POST /api/mfa/resolve`
- `POST /api/mfa/generate-code`
- `GET /api/mfa/history`

---

## 3. Registration Flow

```
POST /api/auth/register
Body: { email, password, displayName }
```

1. **Validate** – `validateRegister()` checks email + password rules.
2. **Check duplicate** – Firestore `users` where `email == trimmedEmail`.
3. **Hash password** – `bcrypt.hash(password, 10)`.
4. **Generate TOTP secret** – `randomBase32(20)` for backup login.
5. **Create user** – Firestore `users` document:
   - `email`, `displayName`, `passwordHash`, `totpSecret`
   - `pqcPublicKey`, `pqcAlgorithm` = null
6. **Create JWT** – `signJwt({ uid: createdRef.id, email })`.
7. **Response** – `{ uid, email, displayName, token, totpSecret }` (totpSecret shown once for backup).

**No JWT verification** – registration is public.

---

## 4. Login Flow (Main Paths)

### Path A: First-time login (no devices)

```
POST /api/auth/login
Body: { email, password, deviceId? }
```

1. Validate email/password.
2. Find user in Firestore.
3. Compare password with `bcrypt.compare()`.
4. Check `devices` collection – if empty:
   - **Create JWT** – `signJwt({ uid, email })`.
   - Return `{ uid, email, displayName, token }`.
5. Mobile then calls `POST /api/devices/register` with JWT to register this device.

---

### Path B: Trusted device (remember me)

```
POST /api/auth/login
Body: { email, password, deviceId }
```

1. Validate and find user.
2. Query `devices` where `uid == uid` and `deviceId == deviceId`.
3. If device exists and `trustedUntil > now`:
   - **Create JWT** – `signJwt({ uid, email })`.
   - Add to `loginHistory`.
   - Return `{ uid, email, displayName, token }`.

---

### Path C: New device – MFA required

```
POST /api/auth/login
Body: { email, password, deviceId }
```

1. Validate, find user, password OK.
2. Device is not trusted (or not found).
3. Check for existing pending challenge for this device (reuse if still valid).
4. **Create MFA challenge** – Firestore `mfaChallenges`:
   - `challengeId`, `uid`, `status: 'pending'`
   - `requestingDeviceId`, `context` (ip, userAgent, timestamp)
   - `expiresAt` (5 min)
5. **Push notification** – Send to other devices’ push tokens.
6. Return `{ requiresMfa: true, challengeId, expiresAt }` – **no JWT yet**.

---

## 5. MFA Approval Flow

### Device 1 (approving device) – polls for pending challenges

```
GET /api/mfa/pending?deviceId=xxx
Header: Authorization: Bearer <JWT>
```

1. **authMiddleware** – verify JWT, set `req.user`.
2. Check `revokedDevices` – if device revoked, return 401.
3. Verify device belongs to user.
4. Find pending challenge in `mfaChallenges` where `uid == uid`, `status == 'pending'`.
5. If challenge’s `requestingDeviceId === deviceId` → return `null` (don’t show approve screen to requesting device).
6. Return `{ challenge }` – Device 1 shows approve/deny UI.

### Device 1 – approves or denies

```
POST /api/mfa/resolve
Body: { challengeId, decision, signature, deviceId, flagged? }
Header: Authorization: Bearer <JWT>
```

1. **authMiddleware** – verify JWT.
2. Find challenge, check status, expiration, ownership.
3. If device has Dilithium2 – verify PQC signature over `challengeId:decision`.
4. Update challenge: `status = decision`, `resolvedAt`, `deviceId`, `signature`.
5. Add to `mfaHistory`.

### Device 2 (requesting device) – polls for approval

```
GET /api/auth/login-status?challengeId=xxx&deviceId=yyy
(No JWT – Device 2 doesn’t have one yet)
```

1. Find challenge by `challengeId`.
2. Ensure `requestingDeviceId === deviceId`.
3. If `status === 'pending'` – return `{ status: 'pending' }`.
4. If `status === 'expired'` or `'denied'` – return `{ status }`.
5. If `status === 'approved'`:
   - **Create JWT** – `signJwt({ uid, email })`.
   - Add to `loginHistory`.
   - Return `{ status: 'approved', token, uid, email, displayName }`.
6. Device 2 stores token and registers device in background.

---

## 6. Backup OTP Flow (other device offline)

```
POST /api/auth/login-with-otp
Body: { challengeId, deviceId, code }
```

1. Find challenge – must be `pending`, not expired.
2. Validate code:
   - **One-time code** – if challenge has `oneTimeCode` and not expired, compare.
   - **TOTP** – else verify against `user.totpSecret` (RFC 6238, 30s step).
3. Update challenge: `status = 'approved'`, `resolvedBy = 'otp'`.
4. **Create JWT** – `signJwt({ uid, email })`.
5. Add to `loginHistory`.
6. Return `{ status: 'approved', token, uid, email, displayName }`.

---

## 7. Device Registration

```
POST /api/devices/register
Header: Authorization: Bearer <JWT>
Body: { deviceId, pqcPublicKey, pqcAlgorithm, platform?, pushToken?, rememberDevice? }
```

1. **authMiddleware** – verify JWT, set `req.user`.
2. Upsert `devices` with:
   - `uid`, `deviceId`, `pqcPublicKey`, `pqcAlgorithm`
   - `pushToken`, `platform`, `trustedUntil` (if rememberDevice)
3. Return `{ deviceId }`.

---

## 8. Login History & Revocation

### Get history

```
GET /api/auth/login-history?deviceId=xxx
Header: Authorization: Bearer <JWT>
```

1. Verify JWT.
2. If `deviceId` provided – check `revokedDevices`; if revoked, return 401.
3. Return `loginHistory` and `firstDeviceId`.

### Delete entry (revoke device)

```
DELETE /api/auth/login-history/:id
Body: { deviceId }  (current device)
Header: Authorization: Bearer <JWT>
```

1. Delete entry from `loginHistory`.
2. Add to `users/{uid}/revokedDevices/{entryDeviceId}`.
3. Next request from that device (e.g. `getLoginHistory`, `getPending`) returns 401.

---

## 9. Data Model (Firestore)

| Collection | Document | Fields |
|------------|----------|--------|
| `users` | `{uid}` | email, displayName, passwordHash, totpSecret, pqcPublicKey, pqcAlgorithm |
| `users/{uid}/loginHistory` | auto-id | deviceId, method, timestamp |
| `users/{uid}/revokedDevices` | `{deviceId}` | revokedAt, revokedBy |
| `users/{uid}/mfaHistory` | auto-id | challengeId, decision, deviceId, timestamp, flagged |
| `devices` | auto-id | uid, deviceId, pqcPublicKey, pqcAlgorithm, pushToken, trustedUntil |
| `mfaChallenges` | auto-id | challengeId, uid, status, requestingDeviceId, context, expiresAt, oneTimeCode |

---

## 10. Summary: Where JWT is Used

| Action | JWT created? | JWT required? |
|--------|--------------|---------------|
| Register | ✅ Yes | ❌ No |
| Login (first time / trusted) | ✅ Yes | ❌ No |
| Login (MFA flow) | ❌ No (yet) | ❌ No |
| getLoginStatus (poll) | ✅ Yes (when approved) | ❌ No |
| loginWithOtp | ✅ Yes | ❌ No |
| Device register | ❌ No | ✅ Yes |
| MFA pending | ❌ No | ✅ Yes |
| MFA resolve | ❌ No | ✅ Yes |
| login-history, me, change-password | ❌ No | ✅ Yes |

---

## 11. Security Notes

- **JWT_SECRET** – Must be 32+ chars, not weak values; used for signing and verification.
- **Passwords** – bcrypt with 10 rounds.
- **Rate limiting** – 30/15min for auth endpoints; 6000/15min for `login-status` (MFA poll).
- **PQC signatures** – Dilithium2 used for approve/deny; verified on backend.
- ** revokedDevices** – Used to invalidate sessions without changing the JWT.
