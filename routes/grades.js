/**
 * ExamGuard Pro — Grades Routes (Canvas Style)
 */
const express = require('express');
const router = express.Router();
const { getDatabase } = require('../config/database');
const { authenticate } = require('../middleware/auth');
const { authorize } = require('../middleware/rbac');
const { ROLES } = require('../config/security');

router.use(authenticate);

// Main Grades View
router.get('/', authorize(ROLES.STUDENT), (req, res) => {
  const db = getDatabase();
  const userId = req.user.id;

  // Get all exams the student has taken or is enrolled in
  const exams = db.prepare(`
    SELECT e.*, u.full_name as instructor_name
    FROM exams e
    JOIN exam_enrollments ee ON e.id = ee.exam_id
    JOIN users u ON e.instructor_id = u.id
    WHERE ee.student_id = ?
    ORDER BY e.created_at DESC
  `).all(userId);

  // For each exam, fetch attempts, highest score, class stats
  for (let exam of exams) {
    // Student's attempts
    const attempts = db.prepare(`
      SELECT * FROM exam_sessions
      WHERE exam_id = ? AND student_id = ? AND status IN ('submitted', 'graded')
      ORDER BY created_at DESC
    `).all(exam.id, userId);
    
    exam.attempts = attempts;
    
    // Find highest attempt
    let highestAttempt = null;
    if (attempts.length > 0) {
      highestAttempt = attempts.reduce((prev, current) => {
        return (prev.percentage > current.percentage) ? prev : current;
      });
    }
    exam.highest_attempt = highestAttempt;

    // Class Stats
    const classStats = db.prepare(`
      SELECT 
        AVG(percentage) as avg_score,
        MAX(percentage) as max_score,
        MIN(percentage) as min_score
      FROM exam_sessions
      WHERE exam_id = ? AND status IN ('submitted', 'graded')
    `).get(exam.id);

    exam.class_stats = classStats;

    // Number of questions
    exam.question_count = db.prepare('SELECT COUNT(*) as count FROM questions WHERE exam_id = ?').get(exam.id).count;
  }

  res.render('grades/index', {
    title: 'My Grades — ExamGuard Pro',
    exams
  });
});

module.exports = router;
