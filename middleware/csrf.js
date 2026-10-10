/**
 * ExamGuard Pro — CSRF Protection Middleware
 * Generates and validates CSRF tokens for state-changing requests
 * STRIDE: Tampering & Spoofing mitigation
 *
 * Strategy:
 *  - Authenticated users: tokens stored in the DB (single-use, per-user).
 *  - Guest users (login/register): tokens signed with HMAC (stateless).
 *    This avoids any FOREIGN KEY issues since guests have no user row.
 */
const crypto = require('crypto');
const { generateCSRFToken } = require('../utils/encryption');
const { getDatabase } = require('../config/database');
const { v4: uuidv4 } = require('uuid');

const CSRF_SECRET = process.env.JWT_SECRET || 'examguard-csrf-fallback-secret';

// ── Helpers ──────────────────────────────────────────────────────────
function signGuestToken(token) {
  return crypto.createHmac('sha256', CSRF_SECRET).update(token).digest('hex');
}

// ── Attach ───────────────────────────────────────────────────────────
function attachCSRFToken(req, res, next) {
  try {
    const token = generateCSRFToken();
    res.locals.csrfToken = token;           // always available in EJS

    if (req.user) {
      // Authenticated — store in DB (single-use)
      const db = getDatabase();
      db.prepare("DELETE FROM csrf_tokens WHERE expires_at < datetime('now')").run();
      db.prepare(
        "INSERT INTO csrf_tokens (id, user_id, token, expires_at) VALUES (?, ?, ?, datetime('now', '+2 hours'))"
      ).run(uuidv4(), req.user.id, token);
    } else {
      // Guest — store a signed copy in a cookie (stateless, no DB needed)
      const sig = signGuestToken(token);
      res.cookie('_csrf_sig', sig, {
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 7200000       // 2 hours
      });
    }
  } catch (err) {
    // Never let CSRF generation crash the entire request
    console.error('[CSRF] Token generation error:', err.message);
    res.locals.csrfToken = '';
  }
  next();
}

// ── Validate ─────────────────────────────────────────────────────────
function validateCSRFToken(req, res, next) {
  // Skip safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Skip exam-session API (JWT-protected already)
  if (req.path.startsWith('/api/exam-session/')) {
    return next();
  }

  const token = req.body?._csrf || req.headers['x-csrf-token'];

  if (!token) {
    return res.status(403).json({ error: 'CSRF token missing' });
  }

  if (req.user) {
    // Authenticated — verify against DB
    const db = getDatabase();
    const row = db.prepare(
      "SELECT id FROM csrf_tokens WHERE user_id = ? AND token = ? AND expires_at > datetime('now')"
    ).get(req.user.id, token);

    if (!row) {
      return res.status(403).json({ error: 'Invalid or expired CSRF token' });
    }
    // Single-use: delete after verification
    db.prepare('DELETE FROM csrf_tokens WHERE id = ?').run(row.id);
  } else {
    // Guest — verify the HMAC signature stored in the cookie
    const sig = req.cookies._csrf_sig;
    if (!sig) {
      return res.status(403).json({ error: 'CSRF session missing' });
    }
    const expected = signGuestToken(token);
    if (sig !== expected) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }

  next();
}

module.exports = { attachCSRFToken, validateCSRFToken };
