/**
 * ExamGuard Pro — Encryption Utilities
 * AES-256-CBC for data encryption + RSA for key exchange
 * STRIDE: Information Disclosure mitigation
 */
const crypto = require('crypto');
const { AES } = require('../config/security');

// ═══════════════════════════════════════
// AES-256-CBC Encryption / Decryption
// ═══════════════════════════════════════

function aesEncrypt(plaintext) {
  try {
    const cipher = crypto.createCipheriv(AES.algorithm, AES.key, AES.iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  } catch (err) {
    throw new Error('Encryption failed: ' + err.message);
  }
}

function aesDecrypt(ciphertext) {
  try {
    const decipher = crypto.createDecipheriv(AES.algorithm, AES.key, AES.iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    throw new Error('Decryption failed: ' + err.message);
  }
}

// AES encrypt with random IV (for chat messages)
function aesEncryptWithIV(plaintext) {
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(AES.algorithm, AES.key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { encrypted, iv: iv.toString('hex') };
  } catch (err) {
    throw new Error('Encryption with IV failed: ' + err.message);
  }
}

function aesDecryptWithIV(ciphertext, ivHex) {
  try {
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(AES.algorithm, AES.key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    throw new Error('Decryption with IV failed: ' + err.message);
  }
}

// ═══════════════════════════════════════
// RSA Key Pair Generation
// ═══════════════════════════════════════

function generateRSAKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

function rsaEncrypt(plaintext, publicKeyPem) {
  const encrypted = crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(plaintext, 'utf8')
  );
  return encrypted.toString('base64');
}

function rsaDecrypt(ciphertext, privateKeyPem) {
  const decrypted = crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(ciphertext, 'base64')
  );
  return decrypted.toString('utf8');
}

// Password Hashing (PBKDF2 with SHA-512)
// This is much more secure than reversible AES encryption for passwords.
function encryptPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const checkHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return hash === checkHash;
  } catch {
    return false;
  }
}

// Digital Signatures for Exam Submissions
function signExamSubmission(sessionId, answers) {
  const secret = process.env.JWT_SECRET || 'fallback-secret';
  const data = JSON.stringify({ sessionId, answers });
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

function verifyExamSignature(signature, sessionId, answers) {
  const expected = signExamSubmission(sessionId, answers);
  return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
}

// ═══════════════════════════════════════
// Secure Random Token Generation
// ═══════════════════════════════════════

function generateSecureToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

function generateCSRFToken() {
  return crypto.randomBytes(24).toString('base64url');
}

module.exports = {
  aesEncrypt,
  aesDecrypt,
  aesEncryptWithIV,
  aesDecryptWithIV,
  generateRSAKeyPair,
  rsaEncrypt,
  rsaDecrypt,
  encryptPassword,
  verifyPassword,
  generateSecureToken,
  generateCSRFToken,
  signExamSubmission,
  verifyExamSignature
};
