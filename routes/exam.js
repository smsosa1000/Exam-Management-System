/**
 * ExamGuard Pro — Exam Routes
 * CRUD operations for exams, exam-taking, and grading
 * STRIDE: Full threat model applied
 */
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../config/database');
const { authenticate } = require('../middleware/auth');
const { authorize } = require('../middleware/rbac');
const { checkExamAccess, checkOwnership } = require('../middleware/abac');
const { logAuditEvent } = require('../middleware/auditLog');
const { validateCSRFToken } = require('../middleware/csrf');
const { validateExam } = require('../middleware/inputValidator');
const { generateSecureToken, aesEncryptWithIV } = require('../utils/encryption');
const { enqueueEmail } = require('../utils/emailQueue');
const { ROLES } = require('../config/security');

router.use(authenticate);

// GET /exams — List exams
router.get('/', (req, res) => {
  const db = getDatabase();
  const user = req.user;
  let exams;
  if (user.role === ROLES.SUPER_ADMIN) {
    exams = db.prepare('SELECT e.*, u.full_name as instructor_name FROM exams e JOIN users u ON e.instructor_id = u.id ORDER BY e.created_at DESC').all();
  } else if (user.role === ROLES.ADMIN) {
    exams = db.prepare('SELECT e.*, u.full_name as instructor_name FROM exams e JOIN users u ON e.instructor_id = u.id WHERE e.instructor_id = ? ORDER BY e.created_at DESC').all(user.id);
  } else {
    exams = db.prepare(
      `SELECT e.*, u.full_name as instructor_name FROM exams e
       JOIN exam_enrollments ee ON e.id = ee.exam_id
       JOIN users u ON e.instructor_id = u.id
       WHERE ee.student_id = ? AND e.is_published = 1 ORDER BY e.start_time ASC`
    ).all(user.id);
  }
  res.render('exams/manage', { title: 'Exams — ExamGuard Pro', exams });
});

// GET /exams/create — Show create form (Instructors only)
router.get('/create', authorize(ROLES.ADMIN), (req, res) => {
  const db = getDatabase();
  const students = db.prepare(`
    SELECT u.id, u.username, u.full_name, u.department,
           (SELECT GROUP_CONCAT(role_id) FROM user_custom_roles WHERE user_id = u.id) as role_ids,
           (SELECT group_id FROM student_group_members WHERE user_id = u.id) as group_id
    FROM users u WHERE u.role = 'student' ORDER BY u.full_name
  `).all();
  const groups = db.prepare('SELECT * FROM student_groups').all();
  const customRoles = db.prepare('SELECT * FROM custom_roles').all();
  
  res.render('exams/create', { 
    title: 'Create Exam — ExamGuard Pro', 
    students, 
    groups, 
    customRoles, 
    error: null, 
    formData: {} 
  });
});

// POST /exams/create — Create new exam
router.post('/create', authorize(ROLES.ADMIN), validateCSRFToken, validateExam, (req, res) => {
  const db = getDatabase();
  const { title, course_name, description, duration_minutes, total_marks, start_time, end_time, anti_cheat_enabled, enrolled_students, questions } = req.body;
  const examId = uuidv4();
  const roomCode = Math.random().toString(36).substring(2, 8).toUpperCase();
  
  const now = new Date();
  const start = new Date(start_time);
  const end = new Date(end_time);

  if (start >= end) {
    const students = getDatabase().prepare('SELECT id, username, full_name, department FROM users WHERE role = ?').all('student');
    return res.status(400).render('exams/create', { title: 'Create Exam — ExamGuard Pro', students, error: 'End time must be after start time', formData: req.body });
  }
  
  if (start < new Date(now.getTime() - 300000)) { // 5 min grace
    const students = getDatabase().prepare('SELECT id, username, full_name, department FROM users WHERE role = ?').all('student');
    return res.status(400).render('exams/create', { title: 'Create Exam — ExamGuard Pro', students, error: 'Start time cannot be in the past. It must be today or in the future.', formData: req.body });
  }

  try {
    db.prepare(`
      INSERT INTO exams (id, title, course_name, description, instructor_id, duration_minutes, total_marks, start_time, end_time, anti_cheat_enabled, room_code, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft')
    `).run(examId, title, course_name, description || '', req.user.id, parseInt(duration_minutes) || 60, parseInt(total_marks) || 100, start_time, end_time, anti_cheat_enabled === 'on' ? 1 : 0, roomCode);

    // Add questions if provided
    if (questions && Array.isArray(questions)) {
      const insertQ = db.prepare(
        'INSERT INTO questions (id, exam_id, question_text, question_type, options, correct_answer, marks, order_index) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      );
      questions.forEach((q, idx) => {
        insertQ.run(uuidv4(), examId, q.text, q.type || 'mcq',
          JSON.stringify(q.options || []), q.correct_answer || '', parseInt(q.marks) || 1, idx + 1);
      });
    }

    // Enroll students
    if (enrolled_students) {
      const studentList = Array.isArray(enrolled_students) ? enrolled_students : [enrolled_students];
      const insertE = db.prepare('INSERT OR IGNORE INTO exam_enrollments (id, exam_id, student_id) VALUES (?, ?, ?)');
      studentList.forEach(sid => insertE.run(uuidv4(), examId, sid));
    }

    logAuditEvent(req.user.id, req.user.username, 'EXAM_CREATED', 'exam', examId, `Title: ${title}`, req.ip, req.get('User-Agent'));
    res.redirect('/exams');
  } catch (err) {
    console.error('[EXAM CREATE ERROR]', err);
    const students = db.prepare('SELECT id, username, full_name, department FROM users WHERE role = ?').all('student');
    res.status(500).render('exams/create', { title: 'Create Exam — ExamGuard Pro', students, error: 'Failed to create exam' });
  }
});

// POST /exams/:examId/publish — Publish exam
router.post('/:examId/publish', authorize(ROLES.ADMIN), validateCSRFToken, checkOwnership('exam'), (req, res) => {
  const db = getDatabase();
  const exam = db.prepare('SELECT * FROM exams WHERE id = ?').get(req.params.examId);
  if (exam && new Date() > new Date(exam.end_time)) {
    return res.status(403).send('Cannot publish an exam that has already ended.');
  }
  db.prepare('UPDATE exams SET is_published = 1, status = ? WHERE id = ?').run('published', req.params.examId);
  
  // Auto-broadcast to enrolled students
  try {
    const students = db.prepare('SELECT student_id FROM exam_enrollments WHERE exam_id = ?').all(req.params.examId);
    if (students.length > 0) {
      const message = `📢 EXAM PUBLISHED: Use Room Code [${exam.room_code}] to join the exam "${exam.title}".`;
      const insertMsg = db.prepare('INSERT INTO chat_messages (id, sender_id, receiver_id, encrypted_message, message_iv) VALUES (?, ?, ?, ?, ?)');
      db.transaction(() => {
        students.forEach(s => {
          const { encrypted, iv } = aesEncryptWithIV(message);
          insertMsg.run(uuidv4(), req.user.id, s.student_id, encrypted, iv);
        });
      })();
    }
  } catch (broadcastErr) {
    console.error('[AUTO-BROADCAST ERROR]', broadcastErr);
  }

  logAuditEvent(req.user.id, req.user.username, 'EXAM_PUBLISHED', 'exam', req.params.examId, '', req.ip, req.get('User-Agent'));
  res.redirect('/dashboard');
});

// POST /exams/join — Student joins exam via room code
router.post('/join', authorize(ROLES.STUDENT), (req, res) => {
  const db = getDatabase();
  const { room_code } = req.body;
  
  if (!room_code) return res.redirect('/dashboard?error=Missing+Room+Code');
  
  try {
    const exam = db.prepare('SELECT id FROM exams WHERE room_code = ?').get(room_code.trim().toUpperCase());
    if (!exam) return res.redirect('/dashboard?error=Invalid+Room+Code');
    
    // Enroll the student
    db.prepare('INSERT OR IGNORE INTO exam_enrollments (id, exam_id, student_id) VALUES (?, ?, ?)')
      .run(uuidv4(), exam.id, req.user.id);
      
    logAuditEvent(req.user.id, req.user.username, 'EXAM_JOINED', 'exam', exam.id, `Joined exam via room code: ${room_code}`, req.ip, req.get('User-Agent'));
    res.redirect('/dashboard?success=Joined+Exam');
  } catch (err) {
    console.error('[JOIN EXAM ERROR]', err);
    res.redirect('/dashboard?error=Server+Error');
  }
});

// POST /exams/:examId/broadcast-code — Broadcast room code to all enrolled students
router.post('/:examId/broadcast-code', authorize(ROLES.ADMIN), checkOwnership('exam'), (req, res) => {
  const db = getDatabase();
  const examId = req.params.examId;
  const exam = db.prepare('SELECT * FROM exams WHERE id = ?').get(examId);

  if (!exam) return res.status(404).json({ error: 'Exam not found' });
  if (exam.status !== 'published') return res.status(400).json({ error: 'Exam must be published to broadcast' });

  try {
    const students = db.prepare('SELECT student_id FROM exam_enrollments WHERE exam_id = ?').all(examId);
    if (students.length === 0) return res.json({ success: true, count: 0, message: 'No students enrolled' });

    const message = `📢 EXAM NOTIFICATION: Use Room Code [${exam.room_code}] to join the exam "${exam.title}".`;
    
    const insertMsg = db.prepare(
      'INSERT INTO chat_messages (id, sender_id, receiver_id, encrypted_message, message_iv) VALUES (?, ?, ?, ?, ?)'
    );

    db.transaction(() => {
      students.forEach(s => {
        const { encrypted, iv } = aesEncryptWithIV(message);
        insertMsg.run(uuidv4(), req.user.id, s.student_id, encrypted, iv);
      });
    })();

    logAuditEvent(req.user.id, req.user.username, 'CODE_BROADCASTED', 'exam', examId, `Broadcasted code to ${students.length} students`, req.ip, req.get('User-Agent'));
    res.json({ success: true, count: students.length });
  } catch (err) {
    console.error('[BROADCAST ERROR]', err);
    res.status(500).json({ error: 'Internal broadcast failure: ' + err.message });
  }
});

// GET /exams/:examId/take — Start taking an exam (Students)
router.get('/:examId/take', authorize(ROLES.STUDENT), checkExamAccess, (req, res) => {
  const db = getDatabase();
  const examId = req.params.examId;
  const exam = db.prepare('SELECT * FROM exams WHERE id = ?').get(examId);
  if (!exam) return res.status(404).render('error', { title: 'Not Found', message: 'Exam not found', code: 404 });

  if (new Date() > new Date(exam.end_time)) {
    return res.status(403).render('error', { title: 'Exam Closed', message: 'This exam has already ended and is no longer available to take.', code: 403 });
  }
  
  if (new Date() < new Date(exam.start_time)) {
    return res.status(403).render('error', { title: 'Not Started', message: 'This exam has not started yet.', code: 403 });
  }

  // Check existing active session
  const existingSession = db.prepare(
    'SELECT * FROM exam_sessions WHERE exam_id = ? AND student_id = ? AND status = ?'
  ).get(examId, req.user.id, 'in_progress');

  let session = existingSession;
  if (!existingSession) {
    // Check max attempts
    const attemptCount = db.prepare(
      'SELECT COUNT(*) as count FROM exam_sessions WHERE exam_id = ? AND student_id = ?'
    ).get(examId, req.user.id).count;
    if (attemptCount >= exam.max_attempts) {
      return res.render('error', { title: 'Limit Reached', message: 'Maximum attempts reached for this exam', code: 403 });
    }
    // Create new session
    const sessionId = uuidv4();
    const sessionToken = generateSecureToken();
    db.prepare(
      `INSERT INTO exam_sessions (id, exam_id, student_id, session_token, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(sessionId, examId, req.user.id, sessionToken, req.ip, req.get('User-Agent'));
    session = db.prepare('SELECT * FROM exam_sessions WHERE id = ?').get(sessionId);
    logAuditEvent(req.user.id, req.user.username, 'EXAM_STARTED', 'exam_session', sessionId, `Exam: ${exam.title}`, req.ip, req.get('User-Agent'));
  }

  let questions = db.prepare('SELECT * FROM questions WHERE exam_id = ? ORDER BY order_index').all(examId);
  if (exam.is_randomized) {
    questions = questions.sort(() => Math.random() - 0.5);
  }
  // Load existing answers
  const existingAnswers = db.prepare('SELECT * FROM answers WHERE session_id = ?').all(session.id);
  const answerMap = {};
  existingAnswers.forEach(a => { answerMap[a.question_id] = a.student_answer; });

  res.render('exams/take', {
    title: `${exam.title} — ExamGuard Pro`, exam, session, questions, answerMap,
    antiCheat: exam.anti_cheat_enabled
  });
});

// POST /exams/:examId/submit — Submit exam answers
router.post('/:examId/submit', authorize(ROLES.STUDENT), validateCSRFToken, async (req, res) => {
  const db = getDatabase();
  const examId = req.params.examId;
  const { session_id, answers } = req.body;
  try {
    const session = db.prepare('SELECT * FROM exam_sessions WHERE id = ? AND student_id = ? AND status = ?')
      .get(session_id, req.user.id, 'in_progress');
    if (!session) return res.status(403).json({ error: 'Invalid or expired exam session' });

    const exam = db.prepare('SELECT * FROM exams WHERE id = ?').get(examId);
    const questions = db.prepare('SELECT * FROM questions WHERE exam_id = ?').all(examId);

    let totalScore = 0;
    const insertAnswer = db.prepare(
      'INSERT OR REPLACE INTO answers (id, session_id, question_id, student_answer, is_correct, marks_awarded) VALUES (?, ?, ?, ?, ?, ?)'
    );

    const gradeTransaction = db.transaction(() => {
      let hasOpenEnded = false;
      if (answers && typeof answers === 'object') {
        for (const [qId, studentAnswer] of Object.entries(answers)) {
          const question = questions.find(q => q.id === qId);
          if (!question) continue;
          
          let finalStudentAnswer = studentAnswer || '';
          if (question.question_type === 'open_ended') {
            hasOpenEnded = true;
            if (finalStudentAnswer.length > 500) {
              finalStudentAnswer = finalStudentAnswer.substring(0, 500);
            }
          }
          
          let isCorrect = 0;
          let marksAwarded = 0;
          if (question.question_type !== 'open_ended') {
            isCorrect = finalStudentAnswer.trim().toLowerCase() === question.correct_answer.trim().toLowerCase() ? 1 : 0;
            marksAwarded = isCorrect ? question.marks : 0;
            totalScore += marksAwarded;
          }
          const existingAnswer = db.prepare('SELECT id FROM answers WHERE session_id = ? AND question_id = ?').get(session_id, qId);
          const answerId = existingAnswer ? existingAnswer.id : uuidv4();
          insertAnswer.run(answerId, session_id, qId, finalStudentAnswer, isCorrect, marksAwarded);
        }
      }
      const percentage = hasOpenEnded ? null : (exam.total_marks > 0 ? Math.round((totalScore / exam.total_marks) * 100) : 0);
      const status = hasOpenEnded ? 'submitted' : 'graded';
      
      db.prepare(
        `UPDATE exam_sessions SET status = ?, score = ?, total_marks = ?, percentage = ?,
         submitted_at = datetime('now') WHERE id = ?`
      ).run(status, totalScore, exam.total_marks, percentage, session_id);
    });
    gradeTransaction();

    logAuditEvent(req.user.id, req.user.username, 'EXAM_SUBMITTED', 'exam_session', session_id,
      `Exam: ${exam.title}, Score: ${totalScore}/${exam.total_marks}`, req.ip, req.get('User-Agent'));

    // Enqueue grade notification email to student (minimal, queued)
    try {
      const student = db.prepare('SELECT email, full_name FROM users WHERE id = ?').get(session.student_id);
      if (student && student.email) {
        const subject = `Your grade for ${exam.title}`;
        const text = `Hello ${student.full_name || ''},\n\nYour exam "${exam.title}" was graded. Score: ${totalScore}/${exam.total_marks}.\n\nRegards, ExamGuard Pro`;
        await enqueueEmail(student.email, subject, text);
        return res.redirect(`/exams/${examId}/results/${session_id}?notification=queued`);
      }
    } catch (e) {
      console.warn('[EMAIL QUEUE] Could not enqueue notification:', e.message);
    }

    res.redirect(`/exams/${examId}/results/${session_id}`);
  } catch (err) {
    console.error('[SUBMIT ERROR]', err);
    res.status(500).json({ error: 'Submission failed' });
  }
});

// GET /exams/:examId/results/:sessionId — View results
router.get('/:examId/results/:sessionId', (req, res) => {
  const db = getDatabase();
  const { examId, sessionId } = req.params;
  const session = db.prepare('SELECT * FROM exam_sessions WHERE id = ?').get(sessionId);
  if (!session) return res.status(404).render('error', { title: 'Not Found', message: 'Session not found', code: 404 });
  if (req.user.role === 'student' && session.student_id !== req.user.id) {
    return res.status(403).render('error', { title: 'Forbidden', message: 'Access denied', code: 403 });
  }
  const exam = db.prepare('SELECT * FROM exams WHERE id = ?').get(examId);
  const questions = db.prepare('SELECT * FROM questions WHERE exam_id = ?').all(examId);
  const answers = db.prepare('SELECT * FROM answers WHERE session_id = ?').all(sessionId);
  const student = db.prepare('SELECT full_name, username FROM users WHERE id = ?').get(session.student_id);
  const proctoring = db.prepare('SELECT * FROM proctoring_events WHERE session_id = ? ORDER BY created_at').all(sessionId);
  res.render('exams/results', {
    title: 'Results — ExamGuard Pro', exam, session, questions, answers, student, proctoring,
    notifyQueued: req.query && req.query.notification === 'queued'
  });
});

// POST /api/exam-session/save-answer — Auto-save answer
router.post('/api/exam-session/save-answer', authorize(ROLES.STUDENT), (req, res) => {
  const db = getDatabase();
  const { session_id, question_id, answer } = req.body;
  try {
    const session = db.prepare('SELECT id FROM exam_sessions WHERE id = ? AND student_id = ? AND status = ?')
      .get(session_id, req.user.id, 'in_progress');
    if (!session) return res.status(403).json({ error: 'Invalid session' });
    
    const question = db.prepare('SELECT question_type FROM questions WHERE id = ?').get(question_id);
    let finalAnswer = answer || '';
    if (question && question.question_type === 'open_ended' && finalAnswer.length > 500) {
      finalAnswer = finalAnswer.substring(0, 500);
    }

    const existing = db.prepare('SELECT id FROM answers WHERE session_id = ? AND question_id = ?').get(session_id, question_id);
    if (existing) {
      db.prepare('UPDATE answers SET student_answer = ?, answered_at = datetime(\'now\') WHERE id = ?').run(finalAnswer, existing.id);
    } else {
      db.prepare('INSERT INTO answers (id, session_id, question_id, student_answer) VALUES (?, ?, ?, ?)')
        .run(uuidv4(), session_id, question_id, finalAnswer);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Save failed' });
  }
});

// POST /api/exam-session/proctoring-event — Log anti-cheat event
router.post('/api/exam-session/proctoring-event', authorize(ROLES.STUDENT), (req, res) => {
  const db = getDatabase();
  const { session_id, event_type, details } = req.body;
  try {
    db.prepare('INSERT INTO proctoring_events (id, session_id, event_type, details) VALUES (?, ?, ?, ?)')
      .run(uuidv4(), session_id, event_type, details || '');
    if (event_type === 'tab_switch') {
      db.prepare('UPDATE exam_sessions SET tab_switches = tab_switches + 1 WHERE id = ?').run(session_id);
    } else if (event_type === 'focus_loss') {
      db.prepare('UPDATE exam_sessions SET focus_loss_count = focus_loss_count + 1 WHERE id = ?').run(session_id);
    }
    const session = db.prepare('SELECT tab_switches, focus_loss_count FROM exam_sessions WHERE id = ?').get(session_id);
    if (session && (session.tab_switches >= 3 || session.focus_loss_count >= 5)) {
      db.prepare('UPDATE exam_sessions SET is_flagged = 1, flag_reason = ? WHERE id = ?')
        .run('Excessive suspicious activity detected', session_id);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Event logging failed' });
  }
});

// GET /exams/:examId/manage-questions — Question management
router.get('/:examId/manage-questions', authorize(ROLES.ADMIN), checkOwnership('exam'), (req, res) => {
  const db = getDatabase();
  const exam = db.prepare('SELECT * FROM exams WHERE id = ?').get(req.params.examId);
  if (exam && (exam.status === 'published' || new Date() > new Date(exam.end_time))) {
    // Still allow viewing, but maybe the UI should disable add/edit.
    // For now, let's allow viewing but add a flag.
  }
  const questions = db.prepare('SELECT * FROM questions WHERE exam_id = ? ORDER BY order_index').all(req.params.examId);
  res.render('exams/manage', { 
    title: 'Manage Questions — ExamGuard Pro', 
    exam, 
    questions, 
    viewMode: 'questions',
    isReadOnly: exam.status === 'published' || new Date() > new Date(exam.end_time)
  });
});

// POST /exams/:examId/add-question — Add question
router.post('/:examId/add-question', authorize(ROLES.ADMIN), checkOwnership('exam'), (req, res) => {
  const db = getDatabase();
  const exam = db.prepare('SELECT * FROM exams WHERE id = ?').get(req.params.examId);
  if (!exam) return res.status(404).json({ error: 'Exam not found' });
  if (exam.status === 'published' || new Date() > new Date(exam.end_time)) {
    return res.status(403).send('Cannot modify a published or ended exam.');
  }

  const { question_text, question_type, options, correct_answer, marks } = req.body;
  
  let optionsArr = [];
  if (question_type === 'true_false') {
    optionsArr = ['True', 'False'];
  } else if (question_type === 'mcq') {
    optionsArr = options ? (Array.isArray(options) ? options : options.split('\n').map(o => o.trim()).filter(Boolean)) : [];
  }

  // Validate correct answer
  let finalCorrectAnswer = correct_answer || '';
  if (question_type === 'mcq' || question_type === 'true_false') {
    if (!optionsArr.includes(finalCorrectAnswer)) {
      return res.status(400).send('Validation Error: Correct answer must be one of the provided options.');
    }
  }

  const maxOrder = db.prepare('SELECT MAX(order_index) as maxIdx FROM questions WHERE exam_id = ?').get(req.params.examId);
  db.prepare('INSERT INTO questions (id, exam_id, question_text, question_type, options, correct_answer, marks, order_index) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(uuidv4(), req.params.examId, question_text, question_type, JSON.stringify(optionsArr), finalCorrectAnswer, parseInt(marks) || 1, (maxOrder?.maxIdx || 0) + 1);
  logAuditEvent(req.user.id, req.user.username, 'QUESTION_ADDED', 'question', req.params.examId, question_text.substring(0, 50), req.ip, req.get('User-Agent'));
  res.redirect(`/exams/${req.params.examId}/manage-questions`);
});

module.exports = router;
