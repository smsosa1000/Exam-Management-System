/**
 * ExamGuard Pro — People, Groups, and Roles Management
 * Canvas-style groups (max 5, auto-lock)
 * Public/Private roles
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

// GET /people — Main view
router.get('/', (req, res) => {
  const db = getDatabase();
  const students = db.prepare(`
    SELECT u.id, u.username, u.full_name, u.department,
           (SELECT GROUP_CONCAT(name) FROM custom_roles r JOIN user_custom_roles ur ON r.id = ur.role_id WHERE ur.user_id = u.id) as roles,
           (SELECT name FROM student_groups g JOIN student_group_members gm ON g.id = gm.group_id WHERE gm.user_id = u.id) as group_name
    FROM users u WHERE u.role = 'student'
  `).all();

  const roles = db.prepare(`
    SELECT r.*, (SELECT COUNT(*) FROM user_custom_roles WHERE role_id = r.id) as member_count 
    FROM custom_roles r
  `).all();

  const groups = db.prepare(`
    SELECT g.*, (SELECT COUNT(*) FROM student_group_members WHERE group_id = g.id) as member_count 
    FROM student_groups g
    ORDER BY g.created_at ASC
  `).all();

  groups.forEach(g => {
    g.students = db.prepare(`
      SELECT u.full_name, u.department 
      FROM users u JOIN student_group_members gm ON u.id = gm.user_id 
      WHERE gm.group_id = ?
    `).all(g.id);
  });

  const myRoles = db.prepare('SELECT role_id FROM user_custom_roles WHERE user_id = ?').all(req.user.id).map(r => r.role_id);
  const myGroup = db.prepare('SELECT group_id FROM student_group_members WHERE user_id = ?').get(req.user.id);

  res.render('people/index', { 
    title: 'People — ExamGuard Pro', 
    students, roles, groups, 
    myRoles, myGroup: myGroup ? myGroup.group_id : null,
    error: req.query.error,
    success: req.query.success
  });
});

// ═══════════════════════════════════════
// GROUPS (Canvas-style)
// ═══════════════════════════════════════

// POST /people/groups/create
router.post('/groups/create', authorize(ROLES.ADMIN, ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  try {
    const groups = db.prepare('SELECT name FROM student_groups WHERE instructor_id = ?').all(req.user.id);
    let maxNum = 0;
    groups.forEach(g => {
      const match = g.name.match(/^Group (\d+)$/i);
      if (match) {
        const num = parseInt(match[1]);
        if (num > maxNum) maxNum = num;
      }
    });
    const name = `Group ${maxNum + 1}`;
    const groupId = uuidv4();
    db.prepare('INSERT INTO student_groups (id, name, description, instructor_id) VALUES (?, ?, ?, ?)')
      .run(groupId, name, 'Auto-generated group', req.user.id);
    res.redirect('/people?success=Group+created#groups');
  } catch (err) {
    res.redirect('/people?error=Failed+to+create+group#groups');
  }
});

// POST /people/groups/join
router.post('/groups/join', authorize(ROLES.STUDENT), (req, res) => {
  const db = getDatabase();
  const { group_id } = req.body;
  try {
    const group = db.prepare('SELECT * FROM student_groups WHERE id = ?').get(group_id);
    const memberCount = db.prepare('SELECT COUNT(*) as count FROM student_group_members WHERE group_id = ?').get(group_id).count;
    
    if (memberCount >= (group.max_members || 5)) {
      return res.redirect('/people?error=Group+is+full#groups');
    }

    // If student is already in a group, remove them from the old one first (auto-switch)
    db.prepare('DELETE FROM student_group_members WHERE user_id = ?').run(req.user.id);

    db.prepare('INSERT INTO student_group_members (user_id, group_id) VALUES (?, ?)')
      .run(req.user.id, group_id);
    res.redirect('/people?success=Joined+group#groups');
  } catch (err) {
    res.redirect('/people?error=Failed+to+join#groups');
  }
});

// POST /people/groups/leave
router.post('/groups/leave', authorize(ROLES.STUDENT), (req, res) => {
  const db = getDatabase();
  const { group_id } = req.body;
  try {
    db.prepare('DELETE FROM student_group_members WHERE user_id = ? AND group_id = ?').run(req.user.id, group_id);
    res.redirect('/people?success=Left+group#groups');
  } catch(err) {
    res.redirect('/people?error=Failed+to+leave+group#groups');
  }
});

// POST /people/groups/delete
router.post('/groups/delete', authorize(ROLES.ADMIN, ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  try {
    db.prepare('DELETE FROM student_groups WHERE id = ?').run(req.body.group_id);
    res.redirect('/people?success=Group+deleted#groups');
  } catch (err) {
    res.redirect('/people?error=Failed+to+delete+group#groups');
  }
});

// ═══════════════════════════════════════
// ROLES (Custom-labeled)
// ═══════════════════════════════════════

// POST /people/roles/create
router.post('/roles/create', authorize(ROLES.ADMIN, ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  const { name, is_public } = req.body;
  try {
    const roleId = uuidv4();
    db.prepare('INSERT INTO custom_roles (id, name, is_public, created_by) VALUES (?, ?, ?, ?)')
      .run(roleId, name, is_public === 'on' ? 1 : 0, req.user.id);
    res.redirect('/people?success=Role+created#roles');
  } catch (err) {
    res.redirect('/people?error=Role+already+exists#roles');
  }
});

// POST /people/roles/join
router.post('/roles/join', authorize(ROLES.STUDENT), (req, res) => {
  const db = getDatabase();
  const { role_id } = req.body;
  const role = db.prepare('SELECT * FROM custom_roles WHERE id = ?').get(role_id);
  if (!role.is_public) return res.redirect('/people?error=Private+role#roles');
  
  db.prepare('INSERT OR IGNORE INTO user_custom_roles (user_id, role_id) VALUES (?, ?)')
    .run(req.user.id, role_id);
  res.redirect('/people?success=Role+added#roles');
});

// POST /people/roles/assign
router.post('/roles/assign', authorize(ROLES.ADMIN, ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  const { role_id, student_ids } = req.body;
  const ids = Array.isArray(student_ids) ? student_ids : [student_ids];
  try {
    db.transaction(() => {
      db.prepare('DELETE FROM user_custom_roles WHERE role_id = ?').run(role_id);
      const insert = db.prepare('INSERT INTO user_custom_roles (user_id, role_id) VALUES (?, ?)');
      ids.forEach(sid => insert.run(sid, role_id));
    })();
    res.redirect('/people?success=Roles+updated#roles');
  } catch (err) {
    res.redirect('/people?error=Failed+to+update#roles');
  }
});

// POST /people/roles/delete
router.post('/roles/delete', authorize(ROLES.ADMIN, ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  try {
    db.prepare('DELETE FROM custom_roles WHERE id = ?').run(req.body.role_id);
    res.redirect('/people?success=Role+deleted#roles');
  } catch (err) {
    res.redirect('/people?error=Failed+to+delete+role#roles');
  }
});

module.exports = router;
