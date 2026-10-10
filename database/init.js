/**
 * ExamGuard Pro — Database Initialization
 * Creates all tables, indexes, and seeds initial data
 * Schema enforces referential integrity and audit trails
 */
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const DB_PATH = path.resolve(__dirname, 'examguard.db');

// PBKDF2 Hashing for passwords
function encryptPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

console.log('╔══════════════════════════════════════════════╗');
console.log('║   ExamGuard Pro — Database Initialization    ║');
console.log('╚══════════════════════════════════════════════╝');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ═══════════════════════════════════════════════
// TABLE DEFINITIONS
// ═══════════════════════════════════════════════

db.exec(`
  -- USERS TABLE
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_encrypted TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('super_admin', 'admin', 'student')),
    department TEXT DEFAULT '',
    clearance TEXT DEFAULT 'standard',
    enrollment_status TEXT DEFAULT 'active' CHECK(enrollment_status IN ('active', 'inactive', 'suspended', 'graduated')),
    is_locked INTEGER DEFAULT 0,
    failed_login_attempts INTEGER DEFAULT 0,
    last_login TEXT,
    lockout_until TEXT,
    current_session_id TEXT,
    two_factor_enabled INTEGER DEFAULT 0,
    two_factor_secret TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  -- EXAMS TABLE
  CREATE TABLE IF NOT EXISTS exams (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    instructor_id TEXT NOT NULL,
    course_name TEXT NOT NULL,
    room_code TEXT UNIQUE,
    duration_minutes INTEGER NOT NULL DEFAULT 60,
    total_marks INTEGER NOT NULL DEFAULT 100,
    pass_marks INTEGER NOT NULL DEFAULT 50,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    is_published INTEGER DEFAULT 0,
    is_randomized INTEGER DEFAULT 1,
    max_attempts INTEGER DEFAULT 1,
    allow_review INTEGER DEFAULT 0,
    anti_cheat_enabled INTEGER DEFAULT 1,
    requires_camera INTEGER DEFAULT 0,
    requires_microphone INTEGER DEFAULT 0,
    status TEXT DEFAULT 'draft' CHECK(status IN ('draft', 'published', 'active', 'completed', 'archived')),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (instructor_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- QUESTIONS TABLE
  CREATE TABLE IF NOT EXISTS questions (
    id TEXT PRIMARY KEY,
    exam_id TEXT NOT NULL,
    question_text TEXT NOT NULL,
    question_type TEXT NOT NULL CHECK(question_type IN ('mcq', 'true_false', 'open_ended')),
    options TEXT DEFAULT '[]',
    correct_answer TEXT NOT NULL,
    marks INTEGER NOT NULL DEFAULT 1,
    order_index INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE
  );

  -- EXAM SESSIONS
  CREATE TABLE IF NOT EXISTS exam_sessions (
    id TEXT PRIMARY KEY,
    exam_id TEXT NOT NULL,
    student_id TEXT NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    start_time TEXT DEFAULT (datetime('now')),
    end_time TEXT,
    status TEXT DEFAULT 'in_progress' CHECK(status IN ('in_progress', 'submitted', 'timed_out', 'flagged', 'graded')),
    score INTEGER,
    total_marks INTEGER,
    percentage REAL,
    tab_switches INTEGER DEFAULT 0,
    focus_loss_count INTEGER DEFAULT 0,
    is_flagged INTEGER DEFAULT 0,
    flag_reason TEXT,
    ip_address TEXT,
    user_agent TEXT,
    submitted_at TEXT,
    graded_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- STUDENT ANSWERS
  CREATE TABLE IF NOT EXISTS answers (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    question_id TEXT NOT NULL,
    student_answer TEXT DEFAULT '',
    is_correct INTEGER,
    marks_awarded INTEGER DEFAULT 0,
    answered_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (session_id) REFERENCES exam_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
  );

  -- EXAM ENROLLMENTS
  CREATE TABLE IF NOT EXISTS exam_enrollments (
    id TEXT PRIMARY KEY,
    exam_id TEXT NOT NULL,
    student_id TEXT NOT NULL,
    enrolled_at TEXT DEFAULT (datetime('now')),
    UNIQUE(exam_id, student_id),
    FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- CHAT MESSAGES
  CREATE TABLE IF NOT EXISTS chat_messages (
    id TEXT PRIMARY KEY,
    sender_id TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    encrypted_message TEXT NOT NULL,
    message_iv TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- AUDIT LOGS
  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    username TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    resource_id TEXT,
    details TEXT,
    ip_address TEXT,
    user_agent TEXT,
    severity TEXT DEFAULT 'info' CHECK(severity IN ('info', 'warning', 'critical', 'error')),
    created_at TEXT DEFAULT (datetime('now'))
  );

  -- CSRF TOKENS
  CREATE TABLE IF NOT EXISTS csrf_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  -- CUSTOM ROLES TABLE
  CREATE TABLE IF NOT EXISTS custom_roles (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    is_public INTEGER DEFAULT 1,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
  );

  -- USER ROLES JUNCTION
  CREATE TABLE IF NOT EXISTS user_custom_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES custom_roles(id) ON DELETE CASCADE
  );

  -- STUDENT GROUPS TABLE (Canvas-style)
  CREATE TABLE IF NOT EXISTS student_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    max_members INTEGER DEFAULT 5,
    instructor_id TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (instructor_id) REFERENCES users(id) ON DELETE SET NULL
  );

  -- GROUP MEMBERS JUNCTION
  CREATE TABLE IF NOT EXISTS student_group_members (
    user_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES student_groups(id) ON DELETE CASCADE
  );

  -- PROCTORING EVENTS
  CREATE TABLE IF NOT EXISTS proctoring_events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK(event_type IN ('tab_switch', 'focus_loss', 'copy_attempt', 'paste_attempt', 'right_click', 'fullscreen_exit', 'suspicious_activity')),
    details TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (session_id) REFERENCES exam_sessions(id) ON DELETE CASCADE
  );

  -- INDEXES
  CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
  CREATE INDEX IF NOT EXISTS idx_exams_instructor ON exams(instructor_id);
  CREATE INDEX IF NOT EXISTS idx_exams_status ON exams(status);
  CREATE INDEX IF NOT EXISTS idx_questions_exam ON questions(exam_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_exam ON exam_sessions(exam_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_student ON exam_sessions(student_id);
  CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
`);

console.log('✅ Tables and indexes created successfully.');

// SEED DATA
const insertUser = db.prepare(`
  INSERT OR REPLACE INTO users (id, username, email, password_encrypted, full_name, role, department, clearance, enrollment_status)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertExam = db.prepare(`
  INSERT OR IGNORE INTO exams (id, title, description, course_name, room_code, instructor_id, duration_minutes, total_marks, start_time, end_time, is_published, status, anti_cheat_enabled, requires_camera, requires_microphone)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertQuestion = db.prepare(`
  INSERT OR IGNORE INTO questions (id, exam_id, question_text, question_type, options, correct_answer, marks, order_index)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertEnrollment = db.prepare(`
  INSERT OR IGNORE INTO exam_enrollments (id, exam_id, student_id)
  VALUES (?, ?, ?)
`);

const insertAudit = db.prepare(`
  INSERT OR IGNORE INTO audit_logs (id, user_id, username, action, resource, details, severity)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

const insertCustomRole = db.prepare(`
  INSERT OR REPLACE INTO custom_roles (id, name, is_public, created_by)
  VALUES (?, ?, ?, ?)
`);

const insertStudentGroup = db.prepare(`
  INSERT OR REPLACE INTO student_groups (id, name, description, instructor_id, max_members)
  VALUES (?, ?, ?, ?, ?)
`);

const insertUserToRole = db.prepare(`
  INSERT OR IGNORE INTO user_custom_roles (user_id, role_id)
  VALUES (?, ?)
`);

const insertUserToGroup = db.prepare(`
  INSERT OR IGNORE INTO student_group_members (user_id, group_id)
  VALUES (?, ?)
`);

// IDs
const superAdminId = 'sa-001';
const admin1Id = 'ad-001';
const admin2Id = 'ad-002';
const student1Id = 'st-001';
const demoStudentId = 'demo-user-id';

db.transaction(() => {
  // Roles
  // 1. Super Admin (Full Control)
  insertUser.run(superAdminId, 'SAdmin', 'superadmin@examguard.edu', encryptPassword('SuperAdmin@2025!'), 'System Administrator', 'super_admin', 'IT Administration', 'top_secret', 'active');
  
  // 2. Instructor (Course & Exam Management)
  insertUser.run(admin1Id, 'Teacher', 'mead@examguard.edu', encryptPassword('Instructor@2025!'), 'Dr. Mohamed Mead', 'admin', 'Computer Science', 'secret', 'active');
  insertUser.run(admin2Id, 'Teacher2', 'ahmed@examguard.edu', encryptPassword('Instructor@2025!'), 'Dr. Ahmed Hassan', 'admin', 'Information Technology', 'secret', 'active');
  insertUser.run(uuidv4(), 'Finance', 'finance@examguard.edu', encryptPassword('Finance@2025!'), 'Finance Admin', 'admin', 'finance', 'secret', 'active');

  // 3. Student (Exam Taking)
  insertUser.run(student1Id, 'Student2', 'samaa@student.examguard.edu', encryptPassword('Student@2025!'), 'Samaa Mohamed', 'student', 'Computer Science', 'standard', 'active');
  insertUser.run(demoStudentId, 'Student', 'demo@examguard.edu', encryptPassword('Dem@1000335'), 'Demo Student Account', 'student', 'Quality Assurance', 'standard', 'active');

  // Fast Demo Exams (3 questions each)
  const exam1Id = 'ex-demo-001';
  insertExam.run(exam1Id, 'Secure Coding Foundations', 'Introductory exam covering standard practices', 'CSE243', 'DEMO11', admin1Id, 60, 15, '2025-01-01 08:00:00', '2027-12-31 23:59:59', 1, 'published', 1, 0, 0);

  const exam2Id = 'ex-demo-002';
  insertExam.run(exam2Id, 'Advanced Cryptography Exam', 'Testing AES, RSA and PKI concepts', 'CSE400', 'CRYPTO', admin1Id, 120, 15, '2025-01-01 08:00:00', '2027-12-31 23:59:59', 1, 'published', 1, 0, 0);
  
  insertQuestion.run('ex1-q1', exam1Id, 'What is 1 + 1?', 'mcq', JSON.stringify(['1', '2', '3', '4']), '2', 10, 1);
  insertQuestion.run('ex1-q2', exam1Id, 'The Earth is flat.', 'true_false', JSON.stringify(['True', 'False']), 'False', 10, 2);
  insertQuestion.run('ex1-q3', exam1Id, 'Briefly explain why security is important in online exams.', 'open_ended', '[]', 'Analysis', 10, 3);

  // Demo Exam 3 (All MCQ for auto-correction test)
  const exam3Id = 'ex-demo-003';
  insertExam.run(exam3Id, 'Fast Demo: ABC Quiz', 'Test for auto-grading logic.', 'ENG101', 'ABC123', admin1Id, 5, 30, '2025-01-01 00:00:00', '2027-12-31 23:59:59', 1, 'published', 1, 0, 0);
  
  insertQuestion.run('ex3-q1', exam3Id, 'Which letter comes after A?', 'mcq', JSON.stringify(['B', 'C', 'D', 'E']), 'B', 10, 1);
  insertQuestion.run('ex3-q2', exam3Id, 'Which letter comes before Z?', 'mcq', JSON.stringify(['X', 'Y', 'W', 'V']), 'Y', 10, 2);
  insertQuestion.run('ex3-q3', exam3Id, 'Is "Apple" a fruit?', 'true_false', JSON.stringify(['True', 'False']), 'True', 10, 3);

  // Enrollments
  const students = [student1Id, demoStudentId];
  const exams = [exam1Id, exam2Id, exam3Id];
  for (const sid of students) {
    for (const eid of exams) {
      insertEnrollment.run(`${eid}-${sid}`, eid, sid);
    }
  }

  // Initial Audit
  insertAudit.run('audit-init-001', superAdminId, 'superadmin', 'SYSTEM_INIT', 'system', 'Full system initialized with 3-role architecture and groups/roles schema.', 'info');

  // Sample Custom Roles
  const compRoleId = 'role-demo-001';
  insertCustomRole.run(compRoleId, 'Competition', 1, admin1Id);
  insertCustomRole.run('role-demo-002', 'Exam Committee', 0, admin1Id);

  // Sample Student Groups
  const group1Id = 'group-demo-001';
  insertStudentGroup.run(group1Id, 'Group 1', 'Capstone Project Group', admin1Id, 5);
  insertStudentGroup.run('group-demo-002', 'Group 2', 'Capstone Project Group', admin1Id, 5);

  // Assign demo student
  insertUserToRole.run(demoStudentId, compRoleId);
  insertUserToGroup.run(demoStudentId, group1Id);
})();

db.close();

console.log('✅ Database restoration complete!');
console.log('✅ Database restoration complete!');
console.log('Super Admin: SAdmin / SuperAdmin@2025!');
console.log('Teacher: Teacher / Instructor@2025!');
console.log('Student: Student / Dem@1000335');
