/**
 * ExamGuard Pro — Authentication Middleware
 * JWT-based session validation
 * STRIDE: Spoofing mitigation
 */
const { verifyToken } = require('../utils/tokenManager');
const { getDatabase } = require('../config/database');

function authenticate(req, res, next) {
  const token = req.cookies?.examguard_token;

  if (!token) {
    if (req.xhr || req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.redirect('/auth/login');
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    res.clearCookie('examguard_token');
    if (req.xhr || req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    return res.redirect('/auth/login');
  }

  // Verify user still exists and is active
  const db = getDatabase();
  const user = db.prepare('SELECT id, username, email, full_name, role, department, enrollment_status, is_locked, current_session_id FROM users WHERE id = ?').get(decoded.userId);

  if (!user || user.is_locked) {
    res.clearCookie('examguard_token');
    if (req.xhr || req.path.startsWith('/api/')) {
      return res.status(403).json({ error: 'Account is locked or does not exist' });
    }
    return res.redirect('/auth/login');
  }

  // SINGLE SESSION ENFORCEMENT
  if (user.current_session_id !== decoded.sid) {
    res.clearCookie('examguard_token');
    if (req.xhr || req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Session invalidated. You have logged in from another device.' });
    }
    return res.render('auth/login', { 
      title: 'Login — ExamGuard Pro', 
      error: 'You have been logged out because your account was used to log in elsewhere.' 
    });
  }

  req.user = user;
  res.locals.user = user;
  next();
}

// Optional auth - doesn't redirect, just populates user if token exists
function optionalAuth(req, res, next) {
  const token = req.cookies?.examguard_token;
  if (token) {
    const decoded = verifyToken(token);
    if (decoded) {
      const db = getDatabase();
      const user = db.prepare('SELECT id, username, full_name, role, department FROM users WHERE id = ?').get(decoded.userId);
      if (user) {
        req.user = user;
        res.locals.user = user;
      }
    }
  }
  next();
}

module.exports = { authenticate, optionalAuth };
