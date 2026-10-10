/**
 * ExamGuard Pro — Custom Roles Routes
 */
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../config/database');
const { authenticate } = require('../middleware/auth');
const { authorize } = require('../middleware/rbac');
const { ROLES } = require('../config/security');
const { logAuditEvent } = require('../middleware/auditLog');

router.use(authenticate);

// POST /roles/create
router.post('/create', authorize(ROLES.ADMIN, ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  const { name, is_public } = req.body;
  try {
    const roleId = uuidv4();
    db.prepare('INSERT INTO custom_roles (id, name, is_public, created_by) VALUES (?, ?, ?, ?)')
      .run(roleId, name, is_public || 0, req.user.id);
    logAuditEvent(req.user.id, req.user.username, 'ROLE_CREATED', 'role', roleId, `Name: ${name}`, req.ip, req.get('User-Agent'));
    res.redirect('/dashboard');
  } catch (err) {
    console.error('[CREATE ROLE ERROR]', err);
    res.redirect('/dashboard');
  }
});

module.exports = router;
