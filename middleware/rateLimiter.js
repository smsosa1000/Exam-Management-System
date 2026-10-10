/**
 * ExamGuard Pro — Rate Limiter Middleware
 * Prevents DoS and brute-force attacks
 * STRIDE: Denial of Service mitigation
 */
const rateLimit = require('express-rate-limit');
const { RATE_LIMIT } = require('../config/security');

// General API rate limiter
const generalLimiter = rateLimit({
  windowMs: RATE_LIMIT.windowMs,
  max: RATE_LIMIT.max,
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Rate limit exceeded',
      message: 'Too many requests from this IP. Please wait before trying again.',
      retryAfter: Math.ceil(RATE_LIMIT.windowMs / 1000)
    });
  }
});

// Strict rate limiter for login (brute-force protection)
const loginLimiter = rateLimit({
  windowMs: RATE_LIMIT.windowMs,
  max: RATE_LIMIT.loginMax,
  message: { error: 'Too many login attempts. Account may be temporarily locked.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too many login attempts',
      message: 'Your IP has been temporarily blocked due to excessive login attempts.',
      retryAfter: Math.ceil(RATE_LIMIT.windowMs / 1000)
    });
  }
});

// Exam submission rate limiter
const examLimiter = rateLimit({
  windowMs: 60000, // 1 minute
  max: 10,
  message: { error: 'Too many exam submissions. Please slow down.' }
});

module.exports = { generalLimiter, loginLimiter, examLimiter };
