/**
 * ExamGuard Pro — Dashboard Routes
 * Role-based dashboard rendering
 */
const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { authenticate } = require('../middleware/auth');
const { ROLES } = require('../config/security');

router.use(authenticate);

router.get('/', (req, res) => {
  const db = getDatabase();
  const user = req.user;
  try {
    if (user.role === ROLES.SUPER_ADMIN) {
      const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
      const totalExams = db.prepare('SELECT COUNT(*) as count FROM exams').get().count;
      const totalSessions = db.prepare('SELECT COUNT(*) as count FROM exam_sessions').get().count;
      const recentLogs = db.prepare('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 10').all();
      const usersByRole = db.prepare('SELECT role, COUNT(*) as count FROM users GROUP BY role').all();
      const recentUsers = db.prepare('SELECT id, username, full_name, role, email, created_at, last_login FROM users ORDER BY created_at DESC LIMIT 5').all();
      res.render('dashboard/superadmin', {
        title: 'Super Admin Dashboard — ExamGuard Pro',
        stats: { totalUsers, totalExams, totalSessions },
        usersByRole, recentLogs, recentUsers
      });
    } else if (user.role === ROLES.ADMIN) {
      const myExams = db.prepare(`
        SELECT e.*, 
               (SELECT AVG(percentage) FROM exam_sessions WHERE exam_id = e.id AND status IN ('graded', 'submitted')) as avg_score,
               (SELECT MIN(percentage) FROM exam_sessions WHERE exam_id = e.id AND status IN ('graded', 'submitted')) as min_score,
               (SELECT MAX(percentage) FROM exam_sessions WHERE exam_id = e.id AND status IN ('graded', 'submitted')) as max_score
        FROM exams e WHERE e.instructor_id = ? ORDER BY e.created_at DESC
      `).all(user.id);

      const totalStudents = db.prepare(
        'SELECT COUNT(DISTINCT student_id) as count FROM exam_enrollments WHERE exam_id IN (SELECT id FROM exams WHERE instructor_id = ?)'
      ).get(user.id).count;
      const totalSessions = db.prepare(
        'SELECT COUNT(*) as count FROM exam_sessions WHERE exam_id IN (SELECT id FROM exams WHERE instructor_id = ?)'
      ).get(user.id).count;
      const recentSubmissions = db.prepare(
        `SELECT es.*, u.full_name as student_name, e.title as exam_title
         FROM exam_sessions es JOIN users u ON es.student_id = u.id
         JOIN exams e ON es.exam_id = e.id WHERE e.instructor_id = ?
         ORDER BY es.created_at DESC LIMIT 10`
      ).all(user.id);
      
      const groups = db.prepare(`
        SELECT g.*, (SELECT COUNT(*) FROM student_group_members WHERE group_id = g.id) as student_count
        FROM student_groups g WHERE g.instructor_id = ? ORDER BY g.created_at ASC
      `).all(user.id);

      const customRoles = db.prepare('SELECT * FROM custom_roles WHERE created_by = ? OR is_public = 1').all(user.id);

      res.render('dashboard/instructor', {
        title: 'Instructor Dashboard — ExamGuard Pro',
        myExams, stats: { totalExams: myExams.length, totalStudents, totalSessions },
        recentSubmissions, groups, customRoles
      });
    } else {
      const enrolledExams = db.prepare(
        `SELECT e.*, u.full_name as instructor_name,
                (SELECT COUNT(*) FROM exam_sessions WHERE exam_id = e.id AND student_id = ?) as attempt_count
         FROM exams e JOIN exam_enrollments ee ON e.id = ee.exam_id
         JOIN users u ON e.instructor_id = u.id
         WHERE ee.student_id = ? AND e.is_published = 1 ORDER BY e.start_time ASC`
      ).all(user.id, user.id);
      const myResults = db.prepare(
        `SELECT es.*, e.title as exam_title, e.total_marks as exam_total
         FROM exam_sessions es JOIN exams e ON es.exam_id = e.id
         WHERE es.student_id = ? AND es.status IN ('submitted', 'graded')
         ORDER BY es.submitted_at DESC`
      ).all(user.id);
      const avgScore = myResults.length > 0
        ? Math.round(myResults.reduce((sum, r) => sum + (r.percentage || 0), 0) / myResults.length) : 0;
      
      const allGroups = db.prepare('SELECT id, name, description FROM student_groups').all();
      const myGroups = db.prepare('SELECT g.id FROM student_groups g JOIN student_group_members sgm ON g.id = sgm.group_id WHERE sgm.user_id = ?').all(user.id);

      res.render('dashboard/student', {
        title: 'Student Dashboard — ExamGuard Pro',
        enrolledExams, myResults,
        stats: { totalEnrolled: enrolledExams.length, totalCompleted: myResults.length, avgScore },
        allGroups, myGroups
      });
    }
  } catch (err) {
    console.error('[DASHBOARD ERROR]', err);
    res.status(500).render('error', { title: 'Error', message: 'Failed to load dashboard', code: 500 });
  }
});

module.exports = router;
