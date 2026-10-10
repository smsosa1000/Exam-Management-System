/**
 * ExamGuard Pro — Main Server
 * Secure Exam Management System
 * CSE243 Secure Programming — 2025
 */
require('dotenv').config();
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const hpp = require('hpp');
const morgan = require('morgan');

// Security Middleware
const { securityHeaders } = require('./middleware/securityHeaders');
const { generalLimiter } = require('./middleware/rateLimiter');
const { auditMiddleware } = require('./middleware/auditLog');
const { sanitizeBody } = require('./middleware/inputValidator');
const { optionalAuth } = require('./middleware/auth');
const { preventNavigationDuringExam } = require('./middleware/abac');
const { attachCSRFToken, validateCSRFToken } = require('./middleware/csrf');

// Routes
const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const examRoutes = require('./routes/exam');
const adminRoutes = require('./routes/admin');
const chatRoutes = require('./routes/chat');
const auditRoutes = require('./routes/audit');
const peopleRoutes = require('./routes/people');

// Initialize database
const { getDatabase } = require('./config/database');

const app = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════
// VIEW ENGINE
// ═══════════════════════════════════════
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ═══════════════════════════════════════
// GLOBAL MIDDLEWARE STACK
// ═══════════════════════════════════════

// Security headers (CSP, X-Frame-Options, etc.)
app.use(securityHeaders);

// Request logging
app.use(morgan('short'));

// Body parsing
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Cookie parsing
app.use(cookieParser());

// HTTP Parameter Pollution protection
app.use(hpp());

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
app.use(generalLimiter);

// Input sanitization
app.use(sanitizeBody);

// Audit logging
app.use(auditMiddleware);

// Optional auth (populates user for all views)
app.use(optionalAuth);

// CSRF token for forms (attach to all requests)
app.use(attachCSRFToken);

// ═══════════════════════════════════════
// ROUTES
// ═══════════════════════════════════════

// Public auth routes (login/register - no CSRF validation yet)
app.use('/auth', authRoutes);

// CSRF validation middleware (applies to everything after this point)
app.use(validateCSRFToken);

// Enforce strict exam navigation rules
app.use(preventNavigationDuringExam);

// Home redirect
app.get('/', (req, res) => {
  if (req.user) return res.redirect('/dashboard');
  res.redirect('/auth/login');
});

app.use('/dashboard', dashboardRoutes);
app.use('/exams', examRoutes);
app.use('/admin', adminRoutes);
app.use('/chat', chatRoutes);
app.use('/audit', auditRoutes);
app.use('/people', peopleRoutes);
app.use('/groups', require('./routes/groups'));
app.use('/roles', require('./routes/roles'));
app.use('/grades', require('./routes/grades'));

// ═══════════════════════════════════════
// ERROR HANDLING
// ═══════════════════════════════════════

// 404
app.use((req, res) => {
  res.status(404).render('error', {
    title: '404 Not Found',
    message: 'The page you are looking for does not exist.',
    code: 404
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err);
  res.status(500).render('error', {
    title: 'Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'An internal error occurred.',
    code: 500
  });
});

// ═══════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════

// Ensure database is initialized
try {
  const db = getDatabase();
  const tableCheck = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").get();
  if (!tableCheck) {
    console.log('⚠️  Database not initialized. Run: npm run init-db');
    process.exit(1);
  }
} catch (err) {
  console.error('Database connection failed:', err.message);
  console.log('Run: npm run init-db');
  process.exit(1);
}

const server = app.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] ExamGuard Pro Server started on port ${PORT}`);
  console.log(`[INFO] Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`[INFO] All Security Modules Initialized.`);

  // Start background email queue worker (optional — only if configured)
  const SENDGRID_KEY = process.env.SENDGRID_API_KEY || '';
  if (SENDGRID_KEY) {
    try {
      const sgMail = require('@sendgrid/mail');
      const { rpopQueue } = require('./utils/redisClient');
      sgMail.setApiKey(SENDGRID_KEY);
      
      setInterval(async () => {
        try {
          const item = await rpopQueue('email_queue');
          if (!item) return;
          const job = JSON.parse(item);
          const msg = {
            to: job.to,
            from: process.env.SENDGRID_FROM || 'no-reply@example.com',
            subject: job.subject,
            text: job.text || job.body || '',
            html: job.html || undefined
          };
          await sgMail.send(msg);
          console.log('[EMAIL WORKER] ✓ Sent email to', job.to);
        } catch (e) {
          // silently log errors, don't spam console
        }
      }, 5000); // check every 5 seconds
      
      console.log('[EMAIL WORKER] Started (polling Redis for jobs)');
    } catch (e) {
      // silently fail if SendGrid setup has issues
    }
  }
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.log(`[WARN] Port ${PORT} is busy. Attempting to free it...`);
    const { execSync } = require('child_process');
    try {
      // Find and kill the process using the port
      const result = execSync(`netstat -ano | findstr :${PORT}`, { encoding: 'utf8' });
      const lines = result.trim().split('\n');
      const pids = new Set();
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        const pid = parts[parts.length - 1];
        if (pid && pid !== '0' && pid !== String(process.pid)) {
          pids.add(pid);
        }
      }
      for (const pid of pids) {
        try { execSync(`taskkill /F /PID ${pid}`, { encoding: 'utf8' }); } catch {}
      }
      console.log('[INFO] Port freed. Restarting in 1 second...');
      setTimeout(() => {
        app.listen(PORT, () => {
          console.log(`[${new Date().toISOString()}] ExamGuard Pro Server started on port ${PORT}`);
          console.log(`[INFO] Environment: ${process.env.NODE_ENV || 'development'}`);
          console.log(`[INFO] All Security Modules Initialized.`);
        });
      }, 1000);
    } catch (e) {
      console.error(`[ERROR] Could not free port ${PORT}. Please run: taskkill /F /IM node.exe`);
      process.exit(1);
    }
  } else {
    console.error('[FATAL]', err);
    process.exit(1);
  }
});

module.exports = app;
