/**
 * Auth controller – register, login, backup OTP, login history, change password.
 */
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { db, admin } = require('./firebase');
const { Expo } = require('expo-server-sdk');

const USERS_COLLECTION = 'users';
const MFA_CHALLENGES_COLLECTION = 'mfaChallenges';
const SALT_ROUNDS = 10;
const expo = new Expo();

// Base32 (RFC 4648) decode for TOTP secret
function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(str).toUpperCase().replace(/\s/g, '').replace(/=+$/, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (let i = 0; i < clean.length; i++) {
    const idx = alphabet.indexOf(clean[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function randomBase32(len = 20) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let s = '';
  const bytes = crypto.randomBytes(len);
  for (let i = 0; i < len; i++) s += alphabet[bytes[i] % 32];
  return s;
}

// Verify 6-digit TOTP code (RFC 6238, 30s step); allow ±1 window for clock skew
function verifyTotp(secretBase32, code) {
  const secret = base32Decode(secretBase32);
  const counter = Math.floor(Date.now() / 1000 / 30);
  const codeStr = String(code).replace(/\s/g, '');
  for (let step = -1; step <= 1; step++) {
    const counterBytes = Buffer.allocUnsafe(8);
    counterBytes.writeBigUInt64BE(BigInt(counter + step), 0);
    const hmac = crypto.createHmac('sha1', secret).update(counterBytes).digest();
    const offset = hmac[19] & 0x0f;
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);
    const expected = (binary % 1000000).toString().padStart(6, '0');
    if (expected === codeStr) return true;
  }
  return false;
}

function signJwt(payload) {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET is not set');
  }
  return jwt.sign(payload, secret, { expiresIn: '1h' });
}

exports.getMe = async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Firestore is not configured' });
    }
    const uid = req.user?.uid;
    if (!uid) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const doc = await db.collection(USERS_COLLECTION).doc(uid).get();
    if (!doc.exists) {
      return res.status(404).json({ message: 'User not found' });
    }
    const { email, displayName } = doc.data();
    return res.status(200).json({ email: email || '', displayName: displayName || null });
  } catch (err) {
    console.error('Error in getMe:', err);
    return res.status(500).json({ message: 'Failed to fetch profile' });
  }
};

exports.changePassword = async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Firestore is not configured' });
    }
    const uid = req.user?.uid;
    if (!uid) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Current password and new password are required' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ message: 'New password must be at least 8 characters' });
    }
    const doc = await db.collection(USERS_COLLECTION).doc(uid).get();
    if (!doc.exists) {
      return res.status(404).json({ message: 'User not found' });
    }
    const user = doc.data();
    const matches = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!matches) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }
    const passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await db.collection(USERS_COLLECTION).doc(uid).update({
      passwordHash,
      updatedAt: new Date().toISOString(),
    });
    return res.status(200).json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Error in changePassword:', err);
    return res.status(500).json({ message: 'Failed to change password' });
  }
};

exports.register = async (req, res) => {
  try {
    if (!db) {
      return res
        .status(500)
        .json({ message: 'Firestore is not configured on the server' });
    }

    const { email, password, displayName } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: 'Email and password are required' });
    }
    if (password.length < 8) {
      return res
        .status(400)
        .json({ message: 'Password must be at least 8 characters' });
    }

    // Check if user already exists
    const existingSnap = await db
      .collection(USERS_COLLECTION)
      .where('email', '==', email.toLowerCase())
      .limit(1)
      .get();

    if (!existingSnap.empty) {
      return res
        .status(409)
        .json({ message: 'A user with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const now = new Date().toISOString();
    const totpSecret = randomBase32(20); // for backup login when other device is offline

    const userDoc = {
      email: email.toLowerCase(),
      displayName: displayName || null,
      passwordHash,
      totpSecret,
      createdAt: now,
      updatedAt: now,
      pqcPublicKey: null,
      pqcAlgorithm: null,
    };

    const createdRef = await db.collection(USERS_COLLECTION).add(userDoc);

    const token = signJwt({ uid: createdRef.id, email: userDoc.email });

    return res.status(201).json({
      uid: createdRef.id,
      email: userDoc.email,
      displayName: userDoc.displayName,
      token,
      totpSecret, // show once: add to authenticator for backup login when other device is offline
    });
  } catch (err) {
    console.error('Error in register:', err);
    return res.status(500).json({ message: 'Registration failed' });
  }
};

exports.login = async (req, res) => {
  try {
    if (!db) {
      return res
        .status(500)
        .json({ message: 'Firestore is not configured on the server' });
    }

    const { email, password, deviceId } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: 'Email and password are required' });
    }

    const userSnap = await db
      .collection(USERS_COLLECTION)
      .where('email', '==', email.toLowerCase())
      .limit(1)
      .get();

    if (userSnap.empty) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const doc = userSnap.docs[0];
    const user = doc.data();
    const uid = doc.id;

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatches) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // First-time login (no devices yet): return token so this device can register
    const devicesSnap = await db
      .collection('devices')
      .where('uid', '==', uid)
      .get();

    if (devicesSnap.empty) {
      const token = signJwt({ uid, email: user.email });
      return res.status(200).json({
        uid,
        email: user.email,
        displayName: user.displayName,
        token,
      });
    }

    // Require approve/deny on another device
    if (!deviceId) {
      return res.status(400).json({
        message: 'deviceId is required for login. Approve or deny on your other device.',
      });
    }

    // Remember device: if this device is trusted, skip MFA
    const deviceSnap = await db
      .collection('devices')
      .where('uid', '==', uid)
      .where('deviceId', '==', deviceId)
      .limit(1)
      .get();
    if (!deviceSnap.empty) {
      const dev = deviceSnap.docs[0].data();
      if (dev.trustedUntil && new Date(dev.trustedUntil) > new Date()) {
        const token = signJwt({ uid, email: user.email });
        await db.collection(USERS_COLLECTION).doc(uid).collection('loginHistory').add({
          deviceId,
          ip: req.ip || req.connection?.remoteAddress || '',
          method: 'remember_device',
          timestamp: new Date().toISOString(),
        });
        return res.status(200).json({
          uid,
          email: user.email,
          displayName: user.displayName,
          token,
        });
      }
    }

    // Reuse existing pending challenge for this device (prevents duplicate challenges from rapid taps)
    const existingSnap = await db
      .collection(MFA_CHALLENGES_COLLECTION)
      .where('uid', '==', uid)
      .where('requestingDeviceId', '==', deviceId)
      .where('status', '==', 'pending')
      .limit(1)
      .get();

    if (!existingSnap.empty) {
      const existing = existingSnap.docs[0].data();
      if (new Date(existing.expiresAt) > new Date()) {
        return res.status(200).json({
          requiresMfa: true,
          challengeId: existing.challengeId,
          expiresAt: existing.expiresAt,
          message: 'Check your other device to approve or deny this login.',
        });
      }
    }

    const challengeId = uuidv4();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
    const context = {
      ip: req.ip || req.connection?.remoteAddress || '',
      userAgent: req.get('user-agent') || '',
      timestamp: new Date().toISOString(),
    };

    const challengeRef = await db.collection(MFA_CHALLENGES_COLLECTION).add({
      challengeId,
      uid,
      status: 'pending',
      context,
      requestingDeviceId: deviceId,
      expiresAt: expiresAt.toISOString(),
      createdAt: new Date().toISOString(),
    });

    // Push to other devices (so user sees approve/deny quickly)
    const messages = [];
    devicesSnap.docs.forEach((d) => {
      const device = d.data();
      if (device.deviceId !== deviceId && Expo.isExpoPushToken(device.pushToken)) {
        messages.push({
          to: device.pushToken,
          sound: 'default',
          title: 'QSafe Login Request',
          body: 'A login was requested. Tap to approve or deny.',
          data: { type: 'mfa_challenge', challengeId, context },
        });
      }
    });

    if (messages.length > 0) {
      const chunks = expo.chunkPushNotifications(messages);
      for (const chunk of chunks) {
        try {
          await expo.sendPushNotificationsAsync(chunk);
        } catch (error) {
          console.error('Error sending push:', error);
        }
      }
    }

    return res.status(200).json({
      requiresMfa: true,
      challengeId,
      expiresAt: expiresAt.toISOString(),
      message: 'Check your other device to approve or deny this login.',
    });
  } catch (err) {
    console.error('Error in login:', err);
    return res.status(500).json({ message: 'Login failed' });
  }
};

// Poll by the device that is waiting for approval (no JWT yet)
exports.getLoginStatus = async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Firestore is not configured' });
    }

    const { challengeId, deviceId } = req.query;
    if (!challengeId || !deviceId) {
      return res.status(400).json({ message: 'challengeId and deviceId are required' });
    }

    const challengeSnap = await db
      .collection(MFA_CHALLENGES_COLLECTION)
      .where('challengeId', '==', challengeId)
      .limit(1)
      .get();

    if (challengeSnap.empty) {
      return res.status(404).json({ status: 'not_found' });
    }

    const challengeDoc = challengeSnap.docs[0];
    const challenge = challengeDoc.data();

    if (challenge.requestingDeviceId !== deviceId) {
      return res.status(403).json({ message: 'Device does not match this challenge' });
    }

    if (challenge.status === 'pending') {
      if (new Date(challenge.expiresAt) < new Date()) {
        await challengeDoc.ref.update({ status: 'expired' });
        return res.status(200).json({ status: 'expired' });
      }
      return res.status(200).json({ status: 'pending' });
    }

    if (challenge.status === 'denied' || challenge.status === 'expired') {
      return res.status(200).json({ status: challenge.status });
    }

    if (challenge.status === 'approved') {
      const userSnap = await db
        .collection(USERS_COLLECTION)
        .doc(challenge.uid)
        .get();
      if (!userSnap.exists) {
        return res.status(500).json({ message: 'User not found' });
      }
      const user = userSnap.data();
      const token = signJwt({ uid: challenge.uid, email: user.email });
      await db.collection(USERS_COLLECTION).doc(challenge.uid).collection('loginHistory').add({
        deviceId: challenge.requestingDeviceId,
        ip: challenge.context?.ip || '',
        method: 'mfa_approved',
        timestamp: new Date().toISOString(),
      });
      return res.status(200).json({
        status: 'approved',
        token,
        uid: challenge.uid,
        email: user.email,
        displayName: user.displayName,
      });
    }

    return res.status(200).json({ status: challenge.status });
  } catch (err) {
    console.error('Error in getLoginStatus:', err);
    return res.status(500).json({ message: 'Failed to get login status' });
  }
};

// Complete login with 6-digit OTP when other device is offline (backup)
exports.loginWithOtp = async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Firestore is not configured' });
    }

    const { challengeId, deviceId, code } = req.body;
    if (!challengeId || !deviceId || !code) {
      return res.status(400).json({
        message: 'challengeId, deviceId, and code are required',
      });
    }

    const challengeSnap = await db
      .collection(MFA_CHALLENGES_COLLECTION)
      .where('challengeId', '==', challengeId)
      .limit(1)
      .get();

    if (challengeSnap.empty) {
      return res.status(404).json({ message: 'Challenge not found' });
    }

    const challengeDoc = challengeSnap.docs[0];
    const challenge = challengeDoc.data();

    if (challenge.requestingDeviceId !== deviceId) {
      return res.status(403).json({ message: 'Device does not match this challenge' });
    }

    if (challenge.status !== 'pending') {
      return res.status(400).json({
        message: `Challenge already ${challenge.status}`,
      });
    }

    if (new Date(challenge.expiresAt) < new Date()) {
      await challengeDoc.ref.update({ status: 'expired' });
      return res.status(400).json({ message: 'Challenge has expired' });
    }

    const userSnap = await db.collection(USERS_COLLECTION).doc(challenge.uid).get();
    if (!userSnap.exists) {
      return res.status(500).json({ message: 'User not found' });
    }
    const user = userSnap.data();

    const codeStr = String(code).replace(/\s/g, '');
    if (!/^\d{6}$/.test(codeStr)) {
      return res.status(400).json({ message: 'Code must be 6 digits' });
    }

    // 1) One-time code from Device 1 (user tapped "Generate code" on approve screen)
    const oneTimeCode = challenge.oneTimeCode;
    const oneTimeCodeExpiresAt = challenge.oneTimeCodeExpiresAt;
    if (oneTimeCode && oneTimeCodeExpiresAt && new Date(oneTimeCodeExpiresAt) > new Date()) {
      if (oneTimeCode !== codeStr) {
        return res.status(401).json({ message: 'Invalid code' });
      }
      await challengeDoc.ref.update({ oneTimeCode: null, oneTimeCodeExpiresAt: null });
    } else {
      // 2) Fallback: TOTP from authenticator (QSafe backup entry added at registration)
      if (!user.totpSecret || !verifyTotp(user.totpSecret, codeStr)) {
        return res.status(401).json({
          message: 'Invalid code. Open QSafe on your other device and tap "Generate code" to get the correct code.',
        });
      }
    }

    await challengeDoc.ref.update({
      status: 'approved',
      resolvedAt: new Date().toISOString(),
      resolvedBy: 'otp',
    });

    const token = signJwt({ uid: challenge.uid, email: user.email });
    await db.collection(USERS_COLLECTION).doc(challenge.uid).collection('loginHistory').add({
      deviceId,
      ip: req.ip || req.connection?.remoteAddress || '',
      method: 'otp',
      timestamp: new Date().toISOString(),
    });
    return res.status(200).json({
      status: 'approved',
      token,
      uid: challenge.uid,
      email: user.email,
      displayName: user.displayName,
    });
  } catch (err) {
    console.error('Error in loginWithOtp:', err);
    return res.status(500).json({ message: 'Failed to complete login' });
  }
};

// Get login history (requires JWT)
exports.getLoginHistory = async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Firestore is not configured' });
    }
    const uid = req.user?.uid;
    if (!uid) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const [historySnap, devicesSnap] = await Promise.all([
      db.collection(USERS_COLLECTION).doc(uid).collection('loginHistory').orderBy('timestamp', 'desc').limit(50).get(),
      db.collection('devices').where('uid', '==', uid).orderBy('createdAt', 'asc').limit(1).get(),
    ]);
    const items = historySnap.docs.map((d) => ({ id: d.id, ...d.data() }));
    const firstDeviceId = !devicesSnap.empty ? devicesSnap.docs[0].data().deviceId : null;
    return res.status(200).json({ history: items, firstDeviceId });
  } catch (err) {
    console.error('Error in getLoginHistory:', err);
    return res.status(500).json({ message: 'Failed to get login history' });
  }
};

exports.deleteLoginHistoryEntry = async (req, res) => {
  try {
    if (!db) return res.status(500).json({ message: 'Firestore is not configured' });
    const uid = req.user?.uid;
    const { id } = req.params;
    const { deviceId: currentDeviceId } = req.body;
    if (!uid || !id) return res.status(400).json({ message: 'Missing id' });
    if (!currentDeviceId) return res.status(400).json({ message: 'deviceId required in body' });
    const docRef = db.collection(USERS_COLLECTION).doc(uid).collection('loginHistory').doc(id);
    const doc = await docRef.get();
    if (!doc.exists) return res.status(404).json({ message: 'Entry not found' });
    const entryDeviceId = doc.data().deviceId;
    if (entryDeviceId === currentDeviceId) return res.status(403).json({ message: 'Cannot delete your own login' });
    const firstSnap = await db.collection('devices').where('uid', '==', uid).orderBy('createdAt', 'asc').limit(1).get();
    const firstDeviceId = !firstSnap.empty ? firstSnap.docs[0].data().deviceId : null;
    if (firstDeviceId && entryDeviceId === firstDeviceId && currentDeviceId !== firstDeviceId) {
      return res.status(403).json({ message: 'Cannot delete first device login' });
    }
    await docRef.delete();
    return res.status(200).json({ message: 'Deleted' });
  } catch (err) {
    console.error('Error in deleteLoginHistoryEntry:', err);
    return res.status(500).json({ message: 'Failed to delete' });
  }
};

// For existing users: set up backup OTP (requires JWT from authMiddleware in route)
exports.setupBackupOtp = async (req, res) => {
  try {
    if (!db) {
      return res.status(500).json({ message: 'Firestore is not configured' });
    }
    const uid = req.user?.uid;
    if (!uid) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const userRef = db.collection(USERS_COLLECTION).doc(uid);
    const userSnap = await userRef.get();
    if (!userSnap.exists) {
      return res.status(404).json({ message: 'User not found' });
    }
    const totpSecret = randomBase32(20);
    await userRef.update({
      totpSecret,
      updatedAt: new Date().toISOString(),
    });
    return res.status(200).json({
      totpSecret,
      message: 'Add this to your authenticator app for backup login when your other device is offline.',
    });
  } catch (err) {
    console.error('Error in setupBackupOtp:', err);
    return res.status(500).json({ message: 'Failed to set up backup OTP' });
  }
};

