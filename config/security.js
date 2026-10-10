/**
 * ExamGuard Pro — Security Configuration
 * Central security constants and policies
 * Aligned with OWASP Top 10 and STRIDE framework
 */
require('dotenv').config();

module.exports = {
  // Password Policy
  PASSWORD_POLICY: {
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireDigit: true,
    requireSpecial: true,
    specialChars: '!@#$%^&*()_+-=[]{}|;:,.<>?'
  },

  // AES-256-CBC Configuration
  AES: {
    algorithm: 'aes-256-cbc',
    key: Buffer.from(process.env.AES_KEY || 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2', 'hex'),
    iv: Buffer.from(process.env.AES_IV || '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d', 'hex')
  },

  // JWT Configuration
  JWT: {
    secret: process.env.JWT_SECRET || 'fallback_secret_change_me',
    expiresIn: process.env.JWT_EXPIRES_IN || '2h',
    algorithm: 'HS256'
  },

  // Refresh token settings (stored JTI in Redis)
  REFRESH: {
    expiresIn: process.env.REFRESH_EXPIRES_IN || '7d',
    ttlSeconds: parseInt(process.env.REFRESH_TTL_SECONDS) || (7 * 24 * 60 * 60),
    maxAge: parseInt(process.env.REFRESH_MAX_AGE_MS) || (7 * 24 * 60 * 60 * 1000)
  },

  // Session / Cookie Configuration
  COOKIE: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: parseInt(process.env.SESSION_MAX_AGE) || 7200000, // 2 hours
    path: '/'
  },

  // Rate Limiting
  RATE_LIMIT: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 60000, // 1 minute (Relaxed for demo)
    max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
    loginMax: parseInt(process.env.LOGIN_RATE_LIMIT_MAX) || 50  // 50 attempts per minute for demo
  },

  // Account Lockout
  LOCKOUT: {
    maxAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5,
    duration: parseInt(process.env.LOCKOUT_DURATION) || 900000 // 15 minutes
  },

  // Roles for RBAC
  ROLES: {
    SUPER_ADMIN: 'super_admin',
    ADMIN: 'admin',        // Instructor / Teacher
    STUDENT: 'student'
  },

  // Content Security Policy
  CSP: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.socket.io"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'", "ws://localhost:*", "wss://localhost:*"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  }
};
