/**
 * ExamGuard Pro — Attribute-Based Access Control (ABAC) Middleware
 * Enforces fine-grained access based on user/resource attributes
 * STRIDE: Elevation of Privilege mitigation
 * 
 * Attributes checked:
 * - enrollment_status (active required for exam access)
 * - exam time window (start_time/end_time)
 * - enrollment in specific exam
 * - department matching
 */
const { getDatabase } = require('../config/database');

/**
 * Check if student is enrolled in the exam and within the time window
 */
function checkExamAccess(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Admins/Super Admins bypass ABAC for exam access
  if (req.user.role === 'super_admin' || req.user.role === 'admin') {
    return next();
  }

  const examId = req.params.examId || req.body.examId;
  if (!examId) {
    return res.status(400).json({ error: 'Exam ID required' });
  }

  const db = getDatabase();

  // Check enrollment status
  if (req.user.enrollment_status !== 'active') {
    return res.status(403).json({ error: 'Your enrollment status does not allow exam access' });
  }

  // Check exam enrollment
  const enrollment = db.prepare(
    'SELECT id FROM exam_enrollments WHERE exam_id = ? AND student_id = ?'
  ).get(examId, req.user.id);

  if (!enrollment) {
    return res.status(403).json({ error: 'You are not enrolled in this exam' });
  }

  // Check exam exists and is published
  const exam = db.prepare(
    'SELECT id, start_time, end_time, status, is_published FROM exams WHERE id = ?'
  ).get(examId);

  if (!exam) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  if (!exam.is_published || exam.status === 'draft') {
    return res.status(403).json({ error: 'This exam is not yet available' });
  }

  // Attach exam to request for downstream use
  req.exam = exam;
  next();
}

/**
 * Check department-level access
 */
function checkDepartmentAccess(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Super admin has global access
  if (req.user.role === 'super_admin') {
    return next();
  }

  const resourceDepartment = req.params.department || req.query.department;
  if (resourceDepartment && req.user.department !== resourceDepartment) {
    return res.status(403).json({ error: 'Cross-department access is not permitted' });
  }

  next();
}

/**
 * Verify user owns the resource or is admin
 */
function checkOwnership(resourceType) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (req.user.role === 'super_admin') return next();

    const db = getDatabase();
    const resourceId = req.params.id || req.params.examId;

    if (resourceType === 'exam') {
      const exam = db.prepare('SELECT instructor_id FROM exams WHERE id = ?').get(resourceId);
      if (!exam || (req.user.role === 'admin' && exam.instructor_id !== req.user.id)) {
        return res.status(403).json({ error: 'You can only manage your own exams' });
      }
    }

    next();
  };
}

/**
 * Prevent student from navigating away from an active exam within the application
 * If they try to visit other pages, the exam is automatically submitted as a violation
 */
function preventNavigationDuringExam(req, res, next) {
  if (!req.user || req.user.role !== 'student') return next();

  // Paths that are allowed during an exam
  const allowedPaths = ['/take', '/submit', '/api/exam-session'];
  const staticExtensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.woff', '.woff2'];
  
  const isAllowed = allowedPaths.some(p => req.path.includes(p)) || 
                    staticExtensions.some(ext => req.path.endsWith(ext));
  
  if (isAllowed) return next();

  const db = getDatabase();
  const activeSession = db.prepare(
    'SELECT id, exam_id FROM exam_sessions WHERE student_id = ? AND status = ?'
  ).get(req.user.id, 'in_progress');

  if (activeSession) {
    // SECURITY VIOLATION: Student tried to navigate away from the exam
    const exam = db.prepare('SELECT title FROM exams WHERE id = ?').get(activeSession.exam_id);
    
    // Auto-submit and flag
    db.prepare(`
      UPDATE exam_sessions 
      SET status = 'flagged', flag_reason = ?, submitted_at = datetime('now')
      WHERE id = ?
    `).run('Student attempted to navigate away from exam page', activeSession.id);

    return res.render('error', { 
      title: 'Exam Terminated', 
      message: `Your exam "${exam?.title || 'Active Exam'}" has been terminated and submitted automatically due to a security violation (Navigating away from the exam page).`, 
      code: 403 
    });
  }

  next();
}

/**
 * ABAC: Enforce role == 'admin' AND department == 'finance' AND 09:00 <= now <= 18:00
 * Requirement for Lab 5 / Final Checklist
 */
function finance_hours_required(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Check role and department (Super admin bypasses)
  if (req.user.role !== 'super_admin') {
    if (req.user.role !== 'admin' || req.user.department !== 'finance') {
      return res.status(403).json({ error: 'Access denied: Requires Finance Admin clearance' });
    }
  }

  // Check time window (09:00 - 18:00)
  const currentHour = new Date().getHours();
  if (currentHour < 9 || currentHour >= 18) {
    return res.status(403).json({ error: 'Access denied: Finance resources are only available between 09:00 and 18:00' });
  }

  next();
}

module.exports = { checkExamAccess, checkDepartmentAccess, checkOwnership, preventNavigationDuringExam, finance_hours_required };
