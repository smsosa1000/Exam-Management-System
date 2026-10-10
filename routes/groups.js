/**
 * ExamGuard Pro — Group Management Routes
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

// POST /groups/create-auto — Auto-create a new group with incremented name
router.post('/create-auto', authorize(ROLES.ADMIN, ROLES.SUPER_ADMIN), (req, res) => {
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
    const newName = `Group ${maxNum + 1}`;
    const groupId = uuidv4();
    db.prepare('INSERT INTO student_groups (id, name, description, instructor_id) VALUES (?, ?, ?, ?)')
      .run(groupId, newName, 'Auto-generated group', req.user.id);
    logAuditEvent(req.user.id, req.user.username, 'GROUP_CREATED', 'group', groupId, `Name: ${newName}`, req.ip, req.get('User-Agent'));
    res.redirect('/dashboard');
  } catch (err) {
    console.error('[CREATE AUTO GROUP ERROR]', err);
    res.redirect('/dashboard');
  }
});

// POST /groups/create — Create a new group
router.post('/create', authorize(ROLES.ADMIN, ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  const { name, description } = req.body;
  try {
    const groupId = uuidv4();
    db.prepare('INSERT INTO student_groups (id, name, description, instructor_id) VALUES (?, ?, ?, ?)')
      .run(groupId, name, description || '', req.user.id);
    logAuditEvent(req.user.id, req.user.username, 'GROUP_CREATED', 'group', groupId, `Name: ${name}`, req.ip, req.get('User-Agent'));
    res.redirect('/dashboard');
  } catch (err) {
    console.error('[CREATE GROUP ERROR]', err);
    res.redirect('/dashboard');
  }
});

// GET /groups/:id/students — Get all students and identify which are in the group
router.get('/:id/students', authorize(ROLES.ADMIN, ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  const allStudents = db.prepare('SELECT id, full_name, department FROM users WHERE role = ?').all('student');
  const groupStudents = db.prepare('SELECT u.id FROM users u JOIN student_group_members sgm ON u.id = sgm.user_id WHERE sgm.group_id = ?').all(req.params.id);
  res.json({ allStudents, groupStudents });
});

// POST /groups/assign — Assign students to a group
router.post('/assign', authorize(ROLES.ADMIN, ROLES.SUPER_ADMIN), (req, res) => {
  const db = getDatabase();
  const { group_id, student_ids } = req.body;
  const ids = Array.isArray(student_ids) ? student_ids : (student_ids ? [student_ids] : []);
  
  try {
    db.transaction(() => {
      // Clear existing assignments for this group
      db.prepare('DELETE FROM student_group_members WHERE group_id = ?').run(group_id);
      // Insert new assignments
      const insert = db.prepare('INSERT INTO student_group_members (user_id, group_id) VALUES (?, ?)');
      ids.forEach(sid => insert.run(sid, group_id));
    })();
    logAuditEvent(req.user.id, req.user.username, 'GROUP_ASSIGNMENT_UPDATED', 'group', group_id, `Assigned ${ids.length} students`, req.ip, req.get('User-Agent'));
    res.redirect('/dashboard');
  } catch (err) {
    console.error('[ASSIGN GROUP ERROR]', err);
    res.redirect('/dashboard');
  }
});

// POST /groups/join — Student joins a group
router.post('/join', authorize(ROLES.STUDENT), (req, res) => {
  const db = getDatabase();
  const { group_id } = req.body;
  try {
    db.prepare('INSERT OR IGNORE INTO student_group_members (user_id, group_id) VALUES (?, ?)')
      .run(req.user.id, group_id);
    logAuditEvent(req.user.id, req.user.username, 'GROUP_JOINED', 'group', group_id, '', req.ip, req.get('User-Agent'));
    res.redirect('/dashboard');
  } catch (err) {
    res.redirect('/dashboard');
  }
});

// POST /groups/leave — Student leaves a group
router.post('/leave', authorize(ROLES.STUDENT), (req, res) => {
  const db = getDatabase();
  const { group_id } = req.body;
  try {
    db.prepare('DELETE FROM student_group_members WHERE user_id = ? AND group_id = ?')
      .run(req.user.id, group_id);
    logAuditEvent(req.user.id, req.user.username, 'GROUP_LEFT', 'group', group_id, '', req.ip, req.get('User-Agent'));
    res.redirect('/dashboard');
  } catch (err) {
    res.redirect('/dashboard');
  }
});

module.exports = router;
