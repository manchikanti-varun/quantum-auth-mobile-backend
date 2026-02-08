/**
 * Generate all PQC keys for QSafe backend:
 * - Dilithium2 for JWT signing
 * - Kyber (ML-KEM-768) for key exchange
 *
 * Add the output to your .env file.
 * @module scripts/generatePqcKeys
 */
const crypto = require('crypto');
const {
  DilithiumKeyPair,
  DilithiumLevel,
} = require('@asanrom/dilithium');
const { MlKem768 } = require('mlkem');

async function main() {
  console.log('# QSafe PQC Key Generation\n');
  console.log('# === Dilithium2 (JWT signing) ===\n');
  const dilithiumSeed = crypto.randomBytes(32);
  const level = DilithiumLevel.get(2);
  const dilKeyPair = DilithiumKeyPair.generate(level, dilithiumSeed);
  const dilPrivate = dilKeyPair.getPrivateKey();
  const dilPublic = dilKeyPair.getPublicKey();

  console.log('PQC_JWT_PUBLIC_KEY=' + dilPublic.toHex());
  console.log('PQC_JWT_PRIVATE_KEY=' + dilPrivate.toHex());

  console.log('\n# === Kyber/ML-KEM-768 (key exchange) ===\n');
  const kyber = new MlKem768();
  const [kyberPk, kyberSk] = await kyber.generateKeyPair();
  console.log('PQC_KYBER_PUBLIC_KEY=' + Buffer.from(kyberPk).toString('hex'));
  console.log('PQC_KYBER_PRIVATE_KEY=' + Buffer.from(kyberSk).toString('hex'));

  console.log('\n# Keep private keys secret. Do not commit to git.');
}

main().catch(console.error);
