/**
 * ExamGuard Pro — Audit Log Middleware
 * Records all critical actions to append-only audit trail
 * STRIDE: Repudiation mitigation (Non-repudiation)
 */
const { getDatabase } = require('../config/database');
const { v4: uuidv4 } = require('uuid');

/**
 * Log an action to the audit trail
 */
function logAuditEvent(userId, username, action, resource, resourceId, details, ipAddress, userAgent, severity = 'info') {
  try {
    const db = getDatabase();
    db.prepare(
      `INSERT INTO audit_logs (id, user_id, username, action, resource, resource_id, details, ip_address, user_agent, severity)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(uuidv4(), userId, username, action, resource, resourceId, details, ipAddress, userAgent, severity);
  } catch (err) {
    console.error('[AUDIT LOG ERROR]', err.message);
  }
}

/**
 * Middleware to auto-log all requests
 */
function auditMiddleware(req, res, next) {
  // Skip static assets and health checks
  if (req.path.startsWith('/css/') || req.path.startsWith('/js/') || req.path.startsWith('/images/') || req.path === '/favicon.ico') {
    return next();
  }

  // Log after response is sent
  res.on('finish', () => {
    // Only log meaningful actions (POST, PUT, DELETE, and important GETs)
    if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
      const userId = req.user?.id || 'anonymous';
      const username = req.user?.username || 'anonymous';
      const severity = res.statusCode >= 400 ? 'warning' : 'info';

      logAuditEvent(
        userId, username,
        `${req.method} ${req.path}`,
        req.path,
        req.params?.id || req.params?.examId || null,
        `Status: ${res.statusCode}`,
        req.ip,
        req.get('User-Agent'),
        severity
      );
    }
  });

  next();
}

module.exports = { logAuditEvent, auditMiddleware };
