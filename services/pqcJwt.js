/**
 * PQC JWT: sign/verify with CRYSTALS-Dilithium2. Replaces HMAC for quantum resistance.
 */
const {
  DilithiumKeyPair,
  DilithiumLevel,
  DilithiumPrivateKey,
  DilithiumPublicKey,
  DilithiumSignature,
} = require('@asanrom/dilithium');

const DILITHIUM_LEVEL = 2;
const ALGORITHM = 'Dilithium2';
const EXPIRES_IN_SEC = 15 * 24 * 3600; // 15 days

function base64urlEncode(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  return buf.toString('base64url');
}

function base64urlDecode(str) {
  return Buffer.from(str, 'base64url');
}

function loadKeys() {
  const pubHex = process.env.PQC_JWT_PUBLIC_KEY;
  const privHex = process.env.PQC_JWT_PRIVATE_KEY;
  if (!pubHex || !privHex) {
    throw new Error(
      'PQC JWT keys not set. Run: npm run generate:pqc and add PQC_JWT_PUBLIC_KEY and PQC_JWT_PRIVATE_KEY to .env'
    );
  }
  const level = DilithiumLevel.get(DILITHIUM_LEVEL);
  const publicKey = DilithiumPublicKey.fromHex(pubHex, level);
  const privateKey = DilithiumPrivateKey.fromHex(privHex, level);
  return { publicKey, privateKey };
}

let cachedKeys = null;

function getKeys() {
  if (!cachedKeys) {
    cachedKeys = loadKeys();
  }
  return cachedKeys;
}

function sign(payload) {
  const { privateKey } = getKeys();
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = {
    ...payload,
    iat: now,
    exp: now + EXPIRES_IN_SEC,
  };
  const header = { alg: ALGORITHM, typ: 'JWT' };
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(fullPayload));
  const signInput = `${headerB64}.${payloadB64}`;
  const messageBytes = Buffer.from(signInput, 'utf8');
  const signature = privateKey.sign(messageBytes);
  const sigHex = signature.toHex();
  const sigB64 = base64urlEncode(Buffer.from(sigHex, 'hex'));
  return `${signInput}.${sigB64}`;
}

function verify(token) {
  const { publicKey } = getKeys();
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid token format');
  }
  const [headerB64, payloadB64, sigB64] = parts;
  const signInput = `${headerB64}.${payloadB64}`;
  const messageBytes = Buffer.from(signInput, 'utf8');
  const sigBuffer = base64urlDecode(sigB64);
  const sigHex = sigBuffer.toString('hex');
  const level = DilithiumLevel.get(DILITHIUM_LEVEL);
  const sig = DilithiumSignature.fromHex(sigHex, level);
  const valid = sig.verify(messageBytes, publicKey);
  if (!valid) {
    throw new Error('Invalid signature');
  }
  const payloadJson = base64urlDecode(payloadB64).toString('utf8');
  const payload = JSON.parse(payloadJson);
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    throw new Error('Token expired');
  }
  return payload;
}

module.exports = { sign, verify };
