/**
 * ExamGuard Pro — Admin Routes
 * User management for Super Admin
 */
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../config/database');
const { authenticate } = require('../middleware/auth');
const { authorize } = require('../middleware/rbac');
const { encryptPassword } = require('../utils/encryption');
const { finance_hours_required } = require('../middleware/abac');
const { logAuditEvent } = require('../middleware/auditLog');
const { ROLES } = require('../config/security');

router.use(authenticate);
router.use(authorize(ROLES.SUPER_ADMIN, ROLES.ADMIN));

// GET /admin/users — List all users
router.get('/users', authorize(ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  const users = db.prepare(
    'SELECT id, username, email, full_name, role, department, enrollment_status, is_locked, last_login, created_at FROM users ORDER BY created_at DESC'
  ).all();
  res.render('admin/users', { title: 'User Management — ExamGuard Pro', users });
});

// POST /admin/users/create — Create user
router.post('/users/create', authorize(ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  const { username, email, password, full_name, role, department } = req.body;
  try {
    const userId = uuidv4();
    db.prepare(
      'INSERT INTO users (id, username, email, password_encrypted, full_name, role, department) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(userId, username, email, encryptPassword(password), full_name, role, department || '');
    logAuditEvent(req.user.id, req.user.username, 'USER_CREATED', 'user', userId, `Created ${role}: ${username}`, req.ip, req.get('User-Agent'));
    res.redirect('/admin/users');
  } catch (err) {
    console.error('[CREATE USER ERROR]', err);
    res.redirect('/admin/users');
  }
});

// POST /admin/users/:id/toggle-lock — Lock/Unlock user
router.post('/users/:id/toggle-lock', authorize(ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  const user = db.prepare('SELECT id, is_locked, username FROM users WHERE id = ?').get(req.params.id);
  if (user) {
    const newStatus = user.is_locked ? 0 : 1;
    db.prepare('UPDATE users SET is_locked = ?, failed_login_attempts = 0, lockout_until = NULL WHERE id = ?').run(newStatus, user.id);
    logAuditEvent(req.user.id, req.user.username, newStatus ? 'USER_LOCKED' : 'USER_UNLOCKED', 'user', user.id, user.username, req.ip, req.get('User-Agent'), 'warning');
  }
  res.redirect('/admin/users');
});

// POST /admin/users/:id/delete — Delete user
router.post('/users/:id/delete', authorize(ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.params.id);
  if (user && req.params.id !== req.user.id) {
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    logAuditEvent(req.user.id, req.user.username, 'USER_DELETED', 'user', req.params.id, user.username, req.ip, req.get('User-Agent'), 'critical');
  }
  res.redirect('/admin/users');
});

// POST /admin/users/:id/change-role — Change user role
router.post('/users/:id/change-role', authorize(ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  const { role } = req.body;
  if (['super_admin', 'admin', 'student'].includes(role)) {
    db.prepare('UPDATE users SET role = ?, updated_at = datetime(\'now\') WHERE id = ?').run(role, req.params.id);
    logAuditEvent(req.user.id, req.user.username, 'ROLE_CHANGED', 'user', req.params.id, `New role: ${role}`, req.ip, req.get('User-Agent'), 'warning');
  }
  res.redirect('/admin/users');
});

// GET /admin/finance-reports — ABAC Demonstration (Lab 5 Requirement)
router.get('/finance-reports', finance_hours_required, (req, res) => {
  logAuditEvent(req.user.id, req.user.username, 'FINANCE_ACCESS', 'reports', null, 'Accessed finance reports', req.ip, req.get('User-Agent'), 'info');
  res.send('<h2>Finance Reports</h2><p>Access Granted: You have the required department and clearance, and you are accessing within permitted hours (09:00 - 18:00).</p><a href="/dashboard">Back to Dashboard</a>');
});
// GET /admin/network — Network Status
router.get('/network', authorize(ROLES.SUPER_ADMIN), (req, res) => {
  const os = require('os');
  const networkInterfaces = os.networkInterfaces();
  const uptime = os.uptime();
  const memory = {
    free: Math.round(os.freemem() / 1024 / 1024),
    total: Math.round(os.totalmem() / 1024 / 1024)
  };
  res.render('admin/network', { 
    title: 'Network Status — ExamGuard Pro', 
    networkInterfaces, 
    uptime, 
    memory 
  });
});

module.exports = router;
