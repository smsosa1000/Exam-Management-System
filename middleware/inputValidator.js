/**
 * ExamGuard Pro — Input Validation Middleware
 * Sanitizes and validates all user input
 * STRIDE: Tampering mitigation (SQLi, XSS prevention)
 */
const validator = require('validator');

/**
 * Sanitize all string fields in req.body
 */
function sanitizeBody(req, res, next) {
  if (req.body && typeof req.body === 'object') {
    for (const key of Object.keys(req.body)) {
      if (typeof req.body[key] === 'string' && key !== 'password' && key !== '_csrf') {
        req.body[key] = validator.trim(req.body[key]);
        req.body[key] = validator.escape(req.body[key]);
      }
    }
  }
  next();
}

/**
 * Validate registration input
 */
function validateRegistration(req, res, next) {
  const { username, email, password, full_name } = req.body;
  const errors = [];

  if (!username || username.length < 3 || username.length > 30) {
    errors.push('Username must be 3-30 characters');
  }
  if (username && !/^[a-zA-Z0-9._]+$/.test(username)) {
    errors.push('Username can only contain letters, numbers, dots, and underscores');
  }
  if (!email || !validator.isEmail(email)) {
    errors.push('Valid email address is required');
  }
  if (!password || password.length < 8) {
    errors.push('Password must be at least 8 characters');
  }
  if (!full_name || full_name.length < 2) {
    errors.push('Full name is required (minimum 2 characters)');
  }

  if (errors.length > 0) {
    return res.status(400).json({ error: 'Validation failed', details: errors });
  }
  next();
}

/**
 * Validate login input
 */
function validateLogin(req, res, next) {
  const { username, password } = req.body;
  const errors = [];

  if (!username || username.length < 1) {
    errors.push('Username is required');
  }
  if (!password || password.length < 1) {
    errors.push('Password is required');
  }

  if (errors.length > 0) {
    return res.status(400).json({ error: 'Validation failed', details: errors });
  }
  next();
}

/**
 * Validate exam creation input
 */
function validateExam(req, res, next) {
  const { title, course_name, duration_minutes, total_marks, start_time, end_time } = req.body;
  const errors = [];

  if (!title || title.length < 3) errors.push('Exam title must be at least 3 characters');
  if (!course_name || course_name.length < 2) errors.push('Course name is required');
  if (!duration_minutes || duration_minutes < 5) errors.push('Duration must be at least 5 minutes');
  if (!total_marks || total_marks < 1) errors.push('Total marks must be at least 1');
  if (!start_time) errors.push('Start time is required');
  if (!end_time) errors.push('End time is required');
  if (start_time && end_time && new Date(start_time) >= new Date(end_time)) {
    errors.push('End time must be after start time');
  }

  if (errors.length > 0) {
    return res.status(400).json({ error: 'Validation failed', details: errors });
  }
  next();
}

module.exports = { sanitizeBody, validateRegistration, validateLogin, validateExam };
