/**
 * ExamGuard Pro — JWT Token Manager
 * Handles token creation, verification, and cookie management
 * STRIDE: Spoofing mitigation
 */
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { JWT, COOKIE, REFRESH } = require('../config/security');
const { setRefreshJti, checkRefreshJti, deleteRefreshJti } = require('./redisClient');

function createToken(payload) {
  return jwt.sign(payload, JWT.secret, {
    expiresIn: JWT.expiresIn,
    algorithm: JWT.algorithm
  });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT.secret, { algorithms: [JWT.algorithm] });
  } catch (err) {
    return null;
  }
}

function setTokenCookie(res, token) {
  res.cookie('examguard_token', token, {
    httpOnly: COOKIE.httpOnly,
    secure: COOKIE.secure,
    sameSite: COOKIE.sameSite,
    maxAge: COOKIE.maxAge,
    path: COOKIE.path
  });
}

function clearTokenCookie(res) {
  res.clearCookie('examguard_token', {
    httpOnly: COOKIE.httpOnly,
    secure: COOKIE.secure,
    sameSite: COOKIE.sameSite,
    path: COOKIE.path
  });
}

// Refresh token helpers
async function createRefreshToken(payload) {
  const jti = uuidv4();
  const token = jwt.sign({ ...payload, jti }, JWT.secret, {
    expiresIn: REFRESH.expiresIn,
    algorithm: JWT.algorithm
  });
  // store jti in redis with TTL (in seconds)
  const ttl = REFRESH.ttlSeconds || (7 * 24 * 60 * 60);
  try { await setRefreshJti(payload.userId, jti, ttl); } catch (e) { /* ignore */ }
  return token;
}

async function verifyRefreshToken(token) {
  try {
    const decoded = jwt.verify(token, JWT.secret, { algorithms: [JWT.algorithm] });
    if (!decoded || !decoded.jti || !decoded.userId) return null;
    const exists = await checkRefreshJti(decoded.userId, decoded.jti);
    return exists ? decoded : null;
  } catch (err) {
    return null;
  }
}

function setRefreshCookie(res, token) {
  // refresh cookie: longer lived, httpOnly
  res.cookie('examguard_refresh', token, {
    httpOnly: true,
    secure: COOKIE.secure,
    sameSite: COOKIE.sameSite,
    maxAge: REFRESH.maxAge || (7 * 24 * 60 * 60 * 1000),
    path: COOKIE.path
  });
}

function clearRefreshCookie(res) {
  res.clearCookie('examguard_refresh', { path: COOKIE.path });
}

module.exports = { createToken, verifyToken, setTokenCookie, clearTokenCookie, createRefreshToken, verifyRefreshToken, setRefreshCookie, clearRefreshCookie, deleteRefreshJti };
