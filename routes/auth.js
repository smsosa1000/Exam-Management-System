/**
 * ExamGuard Pro — Authentication Routes
 * Login, Register, Logout with full security controls
 * STRIDE: Spoofing mitigation
 */
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../config/database');
const { encryptPassword, verifyPassword } = require('../utils/encryption');
const { createToken, setTokenCookie, clearTokenCookie, createRefreshToken, setRefreshCookie } = require('../utils/tokenManager');
const { validatePassword } = require('../utils/helpers');
const { logAuditEvent } = require('../middleware/auditLog');
const { LOCKOUT } = require('../config/security');
const { loginLimiter } = require('../middleware/rateLimiter');
const { validateLogin, validateRegistration } = require('../middleware/inputValidator');
const { authenticate } = require('../middleware/auth');
const { validateCSRFToken } = require('../middleware/csrf');

// ═══════════════════════════════════════
// GET /auth/login — Show login page
// ═══════════════════════════════════════
// Generate a random 5-character alphanumeric CAPTCHA string
function generateCaptchaCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'; // no confusing chars (0/O, 1/l/I)
  let code = '';
  for (let i = 0; i < 5; i++) code += chars.charAt(Math.floor(Math.random() * chars.length));
  return code;
}

router.get('/login', (req, res) => {
  if (req.cookies?.examguard_token) {
    return res.redirect('/dashboard');
  }
  
  // Generate text-based CAPTCHA
  const captchaCode = generateCaptchaCode();
  res.cookie('captcha_answer', captchaCode, { httpOnly: true, sameSite: 'strict', maxAge: 300000 });
  
  res.render('auth/login', { 
    title: 'Login — ExamGuard Pro', 
    error: null, 
    captchaCode: captchaCode
  });
});

// ═══════════════════════════════════════
// POST /auth/login — Process login
// ═══════════════════════════════════════
router.post('/login', loginLimiter, validateLogin, async (req, res) => {
  const { username, password, captcha_input, two_factor_code } = req.body;
  const db = getDatabase();

  try {
    // 1. Verify CAPTCHA (case-sensitive text match)
    const expectedCaptcha = req.cookies.captcha_answer;
    if (!captcha_input || captcha_input !== expectedCaptcha) {
      const newCaptcha = generateCaptchaCode();
      res.cookie('captcha_answer', newCaptcha, { httpOnly: true, sameSite: 'strict', maxAge: 300000 });
      return res.status(400).render('auth/login', {
        title: 'Login — ExamGuard Pro',
        error: 'Incorrect CAPTCHA. Please type the characters exactly as shown.',
        captchaCode: newCaptcha
      });
    }
    res.clearCookie('captcha_answer');

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

    if (!user) {
      const newCaptcha = generateCaptchaCode();
      res.cookie('captcha_answer', newCaptcha, { httpOnly: true, sameSite: 'strict', maxAge: 300000 });
      logAuditEvent(null, username, 'LOGIN_FAILED', 'auth', null, 'User not found', req.ip, req.get('User-Agent'), 'warning');
      return res.status(401).render('auth/login', {
        title: 'Login — ExamGuard Pro',
        error: 'Invalid username or password',
        captchaCode: newCaptcha
      });
    }

    // Check account lockout
    if (user.is_locked && user.lockout_until) {
      const lockoutEnd = new Date(user.lockout_until);
      if (lockoutEnd > new Date()) {
        const newCaptcha = generateCaptchaCode();
        res.cookie('captcha_answer', newCaptcha, { httpOnly: true, sameSite: 'strict', maxAge: 300000 });
        logAuditEvent(user.id, username, 'LOGIN_LOCKED', 'auth', null, 'Account locked - attempt during lockout', req.ip, req.get('User-Agent'), 'warning');
        return res.status(423).render('auth/login', {
          title: 'Login — ExamGuard Pro',
          error: `Account is locked. Try again after ${lockoutEnd.toLocaleTimeString()}`,
          captchaCode: newCaptcha
        });
      } else {
        // Lockout expired, reset
        db.prepare('UPDATE users SET is_locked = 0, failed_login_attempts = 0, lockout_until = NULL WHERE id = ?').run(user.id);
      }
    }

    // Verify password
    if (!verifyPassword(password, user.password_encrypted)) {
      const attempts = (user.failed_login_attempts || 0) + 1;

      if (attempts >= LOCKOUT.maxAttempts) {
        const lockoutUntil = new Date(Date.now() + LOCKOUT.duration).toISOString();
        db.prepare('UPDATE users SET failed_login_attempts = ?, is_locked = 1, lockout_until = ? WHERE id = ?')
          .run(attempts, lockoutUntil, user.id);
        const newCaptcha1 = generateCaptchaCode();
        res.cookie('captcha_answer', newCaptcha1, { httpOnly: true, sameSite: 'strict', maxAge: 300000 });
        logAuditEvent(user.id, username, 'ACCOUNT_LOCKED', 'auth', null, `Locked after ${attempts} failed attempts`, req.ip, req.get('User-Agent'), 'critical');
        return res.status(423).render('auth/login', {
          title: 'Login — ExamGuard Pro',
          error: 'Account locked due to too many failed attempts. Try again in 15 minutes.',
          captchaCode: newCaptcha1
        });
      } else {
        const newCaptcha2 = generateCaptchaCode();
        res.cookie('captcha_answer', newCaptcha2, { httpOnly: true, sameSite: 'strict', maxAge: 300000 });
        db.prepare('UPDATE users SET failed_login_attempts = ? WHERE id = ?').run(attempts, user.id);
        logAuditEvent(user.id, username, 'LOGIN_FAILED', 'auth', null, `Wrong password (attempt ${attempts}/${LOCKOUT.maxAttempts})`, req.ip, req.get('User-Agent'), 'warning');
        return res.status(401).render('auth/login', {
          title: 'Login — ExamGuard Pro',
          error: `Invalid username or password (${LOCKOUT.maxAttempts - attempts} attempts remaining)`,
          captchaCode: newCaptcha2
        });
      }
    }

    // Successful login — reset attempts, set token
    const sessionId = uuidv4();
    db.prepare('UPDATE users SET failed_login_attempts = 0, is_locked = 0, lockout_until = NULL, last_login = datetime(\'now\'), current_session_id = ? WHERE id = ?')
      .run(sessionId, user.id);

    const token = createToken({
      userId: user.id,
      username: user.username,
      role: user.role,
      sid: sessionId
    });

    // 2FA Verification (Demo device code: 12345)
    const DEMO_2FA_CODE = '12345';
    if (!two_factor_code || two_factor_code.trim() !== DEMO_2FA_CODE) {
      const newCaptcha = generateCaptchaCode();
      res.cookie('captcha_answer', newCaptcha, { httpOnly: true, sameSite: 'strict', maxAge: 300000 });
      logAuditEvent(user.id, username, '2FA_FAILED', 'auth', null, 'Invalid 2FA device code', req.ip, req.get('User-Agent'), 'warning');
      return res.status(401).render('auth/login', {
        title: 'Login — ExamGuard Pro',
        error: 'Invalid 2FA Device Code. Enter the code from your authenticator device.',
        captchaCode: newCaptcha
      });
    }

    setTokenCookie(res, token);
    // Create and set a refresh token (JTI is stored in Redis)
    try {
      const refresh = await createRefreshToken({ userId: user.id });
      setRefreshCookie(res, refresh);
    } catch (e) {
      console.warn('[REFRESH TOKEN] Could not create refresh token:', e.message);
    }

    logAuditEvent(user.id, username, 'LOGIN_SUCCESS', 'auth', null, `Role: ${user.role} | SID: ${sessionId}`, req.ip, req.get('User-Agent'), 'info');

    res.redirect('/dashboard');

  } catch (err) {
    console.error('[LOGIN ERROR]', err);
    const newCaptcha = generateCaptchaCode();
    res.cookie('captcha_answer', newCaptcha, { httpOnly: true, sameSite: 'strict', maxAge: 300000 });
    res.status(500).render('auth/login', {
      title: 'Login — ExamGuard Pro',
      error: 'An internal error occurred. Please try again.',
      captchaCode: newCaptcha
    });
  }
});

// ═══════════════════════════════════════
// GET /auth/register — Show registration page
// ═══════════════════════════════════════
router.get('/register', (req, res) => {
  if (req.cookies?.examguard_token) {
    return res.redirect('/dashboard');
  }
  res.render('auth/register', { title: 'Register — ExamGuard Pro', error: null, success: null, formData: {} });
});

// ═══════════════════════════════════════
// POST /auth/register — Process registration
// ═══════════════════════════════════════
router.post('/register', validateRegistration, validateCSRFToken, (req, res) => {
  const { username, email, password, confirm_password, full_name, department } = req.body;
  const db = getDatabase();

  try {
    // Validate password match
    if (password !== confirm_password) {
      return res.status(400).render('auth/register', {
        title: 'Register — ExamGuard Pro',
        error: 'Passwords do not match', success: null, formData: req.body
      });
    }

    // Validate password strength
    const pwCheck = validatePassword(password);
    if (!pwCheck.isValid) {
      return res.status(400).render('auth/register', {
        title: 'Register — ExamGuard Pro',
        error: pwCheck.errors.join('. '), success: null, formData: req.body
      });
    }

    // Check existing user
    const existing = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
    if (existing) {
      return res.status(409).render('auth/register', {
        title: 'Register — ExamGuard Pro',
        error: 'Username or email already exists', success: null, formData: req.body
      });
    }

    // Create user (default role: student)
    const userId = uuidv4();
    const encrypted = encryptPassword(password);
    db.prepare(
      'INSERT INTO users (id, username, email, password_encrypted, full_name, role, department) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(userId, username, email, encrypted, full_name, 'student', department || '');

    logAuditEvent(userId, username, 'USER_REGISTERED', 'auth', userId, `New student registration`, req.ip, req.get('User-Agent'), 'info');

    res.render('auth/register', {
      title: 'Register — ExamGuard Pro',
      error: null,
      success: 'Registration successful! You can now log in.', formData: {}
    });

  } catch (err) {
    console.error('[REGISTER ERROR]', err);
    res.status(500).render('auth/register', {
      title: 'Register — ExamGuard Pro',
      error: 'Registration failed. Please try again.', success: null, formData: req.body
    });
  }
});

// ═══════════════════════════════════════
// GET /auth/logout — Logout user
// ═══════════════════════════════════════
router.get('/logout', (req, res) => {
  if (req.cookies?.examguard_token) {
    const { verifyToken } = require('../utils/tokenManager');
    const decoded = verifyToken(req.cookies.examguard_token);
    if (decoded) {
      logAuditEvent(decoded.userId, decoded.username, 'LOGOUT', 'auth', null, 'User logged out', req.ip, req.get('User-Agent'), 'info');
    }
  }
  clearTokenCookie(res);
  res.redirect('/auth/login');
});

module.exports = router;
