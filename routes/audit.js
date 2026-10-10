/**
 * ExamGuard Pro — Audit Log Routes
 * View-only audit trail for administrators
 * STRIDE: Repudiation mitigation
 */
const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { authenticate } = require('../middleware/auth');
const { authorize } = require('../middleware/rbac');
const { ROLES } = require('../config/security');

router.use(authenticate);
router.use(authorize(ROLES.SUPER_ADMIN, ROLES.ADMIN));

// GET /audit — View audit logs
router.get('/', (req, res) => {
  const db = getDatabase();
  const { severity, action, page = 1 } = req.query;
  const limit = 50;
  const offset = (parseInt(page) - 1) * limit;

  let query = 'SELECT * FROM audit_logs WHERE 1=1';
  const params = [];

  if (severity) { query += ' AND severity = ?'; params.push(severity); }
  if (action) { query += ' AND action LIKE ?'; params.push(`%${action}%`); }

  // Non-super-admins can only see their own logs
  if (req.user.role !== ROLES.SUPER_ADMIN) {
    query += ' AND user_id = ?';
    params.push(req.user.id);
  }

  const total = db.prepare(query.replace('SELECT *', 'SELECT COUNT(*) as count')).get(...params).count;
  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const logs = db.prepare(query).all(...params);
  const totalPages = Math.ceil(total / limit);

  res.render('audit/logs', {
    title: 'Audit Logs — ExamGuard Pro',
    logs, currentPage: parseInt(page), totalPages, total, severity, action
  });
});

module.exports = router;
