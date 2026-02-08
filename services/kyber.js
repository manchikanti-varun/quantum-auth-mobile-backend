/**
 * CRYSTALS-Kyber (ML-KEM-768) for quantum-resistant key exchange.
 * Encapsulation/decapsulation and AES key derivation from shared secret.
 */
const { MlKem768 } = require('mlkem');
const crypto = require('crypto');

const KEY_SIZE = 32; // Shared secret is 32 bytes from ML-KEM-768

let serverKeypair = null;

async function loadOrGenerateServerKeypair() {
  if (serverKeypair) return serverKeypair;
  const pkHex = process.env.PQC_KYBER_PUBLIC_KEY;
  const skHex = process.env.PQC_KYBER_PRIVATE_KEY;
  if (pkHex && skHex) {
    serverKeypair = {
      publicKey: Buffer.from(pkHex, 'hex'),
      privateKey: Buffer.from(skHex, 'hex'),
    };
    return serverKeypair;
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'PQC_KYBER_PUBLIC_KEY and PQC_KYBER_PRIVATE_KEY must be set in production. Run: node scripts/generatePqcKeys.js'
    );
  }
  const kyber = new MlKem768();
  const [pk, sk] = await kyber.generateKeyPair();
  serverKeypair = {
    publicKey: Buffer.from(pk),
    privateKey: Buffer.from(sk),
  };
  return serverKeypair;
}

async function getServerPublicKey() {
  const { publicKey } = await loadOrGenerateServerKeypair();
  return publicKey.toString('hex');
}

async function encapsulate(pkHex) {
  const kyber = new MlKem768();
  const pk = Buffer.from(pkHex, 'hex');
  const [ct, ss] = await kyber.encap(new Uint8Array(pk));
  return {
    ciphertext: Buffer.from(ct).toString('hex'),
    sharedSecret: Buffer.from(ss).toString('hex'),
  };
}

async function decapsulate(ctHex) {
  const { privateKey } = await loadOrGenerateServerKeypair();
  const kyber = new MlKem768();
  const ct = Buffer.from(ctHex, 'hex');
  const ss = await kyber.decap(new Uint8Array(ct), new Uint8Array(privateKey));
  return Buffer.from(ss).toString('hex');
}

function deriveAesKey(sharedSecretHex, context = 'qsafe-v1') {
  return crypto
    .createHash('sha256')
    .update(Buffer.from(sharedSecretHex, 'hex'))
    .update(Buffer.from(context, 'utf8'))
    .digest();
}

module.exports = {
  getServerPublicKey,
  encapsulate,
  decapsulate,
  deriveAesKey,
  loadOrGenerateServerKeypair,
};
