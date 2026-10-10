-- ══════════════════════════════════════════════════════════════
-- ExamGuard Pro — Complete Database Schema & Seed Data
-- MySQL Compatible Version
-- CSE243 Secure Programming — May 2025
-- ══════════════════════════════════════════════════════════════

DROP DATABASE IF EXISTS examguard_pro;
CREATE DATABASE examguard_pro CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE examguard_pro;

-- ══════════════════════════════════════════════════════════════
-- TABLE DEFINITIONS
-- ══════════════════════════════════════════════════════════════

-- USERS TABLE
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(30) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_encrypted TEXT NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role ENUM('super_admin', 'admin', 'student') NOT NULL,
    department VARCHAR(100) DEFAULT '',
    clearance VARCHAR(20) DEFAULT 'standard',
    enrollment_status ENUM('active', 'inactive', 'suspended', 'graduated') DEFAULT 'active',
    is_locked TINYINT(1) DEFAULT 0,
    failed_login_attempts INT DEFAULT 0,
    last_login DATETIME NULL,
    lockout_until DATETIME NULL,
    current_session_id VARCHAR(36) NULL,
    two_factor_enabled TINYINT(1) DEFAULT 0,
    two_factor_secret VARCHAR(255) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- EXAMS TABLE
CREATE TABLE IF NOT EXISTS exams (
    id VARCHAR(36) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description VARCHAR(500) DEFAULT '',
    instructor_id VARCHAR(36) NOT NULL,
    course_name VARCHAR(100) NOT NULL,
    room_code VARCHAR(20) UNIQUE,
    duration_minutes INT NOT NULL DEFAULT 60,
    total_marks INT NOT NULL DEFAULT 100,
    pass_marks INT NOT NULL DEFAULT 50,
    start_time DATETIME NOT NULL,
    end_time DATETIME NOT NULL,
    is_published TINYINT(1) DEFAULT 0,
    is_randomized TINYINT(1) DEFAULT 1,
    max_attempts INT DEFAULT 1,
    allow_review TINYINT(1) DEFAULT 0,
    anti_cheat_enabled TINYINT(1) DEFAULT 1,
    requires_camera TINYINT(1) DEFAULT 0,
    requires_microphone TINYINT(1) DEFAULT 0,
    status ENUM('draft', 'published', 'active', 'completed', 'archived') DEFAULT 'draft',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (instructor_id) REFERENCES users(id) ON DELETE CASCADE
);

-- QUESTIONS TABLE
CREATE TABLE IF NOT EXISTS questions (
    id VARCHAR(36) PRIMARY KEY,
    exam_id VARCHAR(36) NOT NULL,
    question_text TEXT NOT NULL,
    question_type ENUM('mcq', 'true_false', 'open_ended') NOT NULL,
    options JSON,
    correct_answer TEXT NOT NULL,
    marks INT NOT NULL DEFAULT 1,
    order_index INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE
);

-- EXAM SESSIONS
CREATE TABLE IF NOT EXISTS exam_sessions (
    id VARCHAR(36) PRIMARY KEY,
    exam_id VARCHAR(36) NOT NULL,
    student_id VARCHAR(36) NOT NULL,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME NULL,
    status ENUM('in_progress', 'submitted', 'timed_out', 'flagged', 'graded') DEFAULT 'in_progress',
    score INT NULL,
    total_marks INT NULL,
    percentage DECIMAL(5,2) NULL,
    tab_switches INT DEFAULT 0,
    focus_loss_count INT DEFAULT 0,
    is_flagged TINYINT(1) DEFAULT 0,
    flag_reason TEXT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    submitted_at DATETIME NULL,
    graded_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);

-- STUDENT ANSWERS
CREATE TABLE IF NOT EXISTS answers (
    id VARCHAR(36) PRIMARY KEY,
    session_id VARCHAR(36) NOT NULL,
    question_id VARCHAR(36) NOT NULL,
    student_answer TEXT,
    is_correct TINYINT(1) NULL,
    marks_awarded INT DEFAULT 0,
    answered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES exam_sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
);

-- EXAM ENROLLMENTS
CREATE TABLE IF NOT EXISTS exam_enrollments (
    id VARCHAR(36) PRIMARY KEY,
    exam_id VARCHAR(36) NOT NULL,
    student_id VARCHAR(36) NOT NULL,
    enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_enrollment (exam_id, student_id),
    FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);

-- CHAT MESSAGES
CREATE TABLE IF NOT EXISTS chat_messages (
    id VARCHAR(36) PRIMARY KEY,
    sender_id VARCHAR(36) NOT NULL,
    receiver_id VARCHAR(36) NOT NULL,
    encrypted_message TEXT NOT NULL,
    message_iv VARCHAR(64) NOT NULL,
    is_read TINYINT(1) DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
);

-- AUDIT LOGS (append-only by design — no UPDATE/DELETE permitted)
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NULL,
    username VARCHAR(30) NULL,
    action VARCHAR(255) NOT NULL,
    resource VARCHAR(255) NULL,
    resource_id VARCHAR(36) NULL,
    details TEXT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    severity ENUM('info', 'warning', 'critical', 'error') DEFAULT 'info',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- CSRF TOKENS
CREATE TABLE IF NOT EXISTS csrf_tokens (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- CUSTOM ROLES TABLE
CREATE TABLE IF NOT EXISTS custom_roles (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    is_public TINYINT(1) DEFAULT 1,
    created_by VARCHAR(36) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

-- USER ROLES JUNCTION
CREATE TABLE IF NOT EXISTS user_custom_roles (
    user_id VARCHAR(36) NOT NULL,
    role_id VARCHAR(36) NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES custom_roles(id) ON DELETE CASCADE
);

-- STUDENT GROUPS TABLE (Canvas-style)
CREATE TABLE IF NOT EXISTS student_groups (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT NULL,
    max_members INT DEFAULT 5,
    instructor_id VARCHAR(36) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (instructor_id) REFERENCES users(id) ON DELETE SET NULL
);

-- GROUP MEMBERS JUNCTION
CREATE TABLE IF NOT EXISTS student_group_members (
    user_id VARCHAR(36) NOT NULL,
    group_id VARCHAR(36) NOT NULL,
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES student_groups(id) ON DELETE CASCADE
);

-- PROCTORING EVENTS
CREATE TABLE IF NOT EXISTS proctoring_events (
    id VARCHAR(36) PRIMARY KEY,
    session_id VARCHAR(36) NOT NULL,
    event_type ENUM('tab_switch', 'focus_loss', 'copy_attempt', 'paste_attempt', 'right_click', 'fullscreen_exit', 'suspicious_activity') NOT NULL,
    details TEXT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES exam_sessions(id) ON DELETE CASCADE
);

-- ══════════════════════════════════════════════════════════════
-- INDEXES
-- ══════════════════════════════════════════════════════════════

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_exams_instructor ON exams(instructor_id);
CREATE INDEX idx_exams_status ON exams(status);
CREATE INDEX idx_questions_exam ON questions(exam_id);
CREATE INDEX idx_sessions_exam ON exam_sessions(exam_id);
CREATE INDEX idx_sessions_student ON exam_sessions(student_id);
CREATE INDEX idx_audit_user ON audit_logs(user_id);

-- ══════════════════════════════════════════════════════════════
-- TRIGGER: Enforce append-only on audit_logs (no UPDATE/DELETE)
-- ══════════════════════════════════════════════════════════════

DELIMITER $$

CREATE TRIGGER prevent_audit_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'UPDATE operations are not permitted on audit_logs (append-only table)';
END$$

CREATE TRIGGER prevent_audit_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'DELETE operations are not permitted on audit_logs (append-only table)';
END$$

DELIMITER ;

-- ══════════════════════════════════════════════════════════════
-- SEED DATA
-- ══════════════════════════════════════════════════════════════

-- NOTE: Passwords below are PBKDF2-SHA512 hashes (salt:hash format).
-- These are the EXACT hashes generated by the application's encryptPassword() function.
-- In a real environment, these would be generated at runtime.
-- For demo purposes, the plaintext passwords are listed in comments.

-- ─── USERS ───

-- Super Admin: SAdmin / SuperAdmin@2025!
INSERT INTO users (id, username, email, password_encrypted, full_name, role, department, clearance, enrollment_status) VALUES
('sa-001', 'SAdmin', 'superadmin@examguard.edu', 'PBKDF2_HASH_PLACEHOLDER_SuperAdmin@2025!', 'System Administrator', 'super_admin', 'IT Administration', 'top_secret', 'active');

-- Instructor 1: Teacher / Instructor@2025!
INSERT INTO users (id, username, email, password_encrypted, full_name, role, department, clearance, enrollment_status) VALUES
('ad-001', 'Teacher', 'mead@examguard.edu', 'PBKDF2_HASH_PLACEHOLDER_Instructor@2025!', 'Dr. Mohamed Mead', 'admin', 'Computer Science', 'secret', 'active');

-- Instructor 2: Teacher2 / Instructor@2025!
INSERT INTO users (id, username, email, password_encrypted, full_name, role, department, clearance, enrollment_status) VALUES
('ad-002', 'Teacher2', 'ahmed@examguard.edu', 'PBKDF2_HASH_PLACEHOLDER_Instructor@2025!', 'Dr. Ahmed Hassan', 'admin', 'Information Technology', 'secret', 'active');

-- Finance Admin: Finance / Finance@2025!
INSERT INTO users (id, username, email, password_encrypted, full_name, role, department, clearance, enrollment_status) VALUES
('fin-001', 'Finance', 'finance@examguard.edu', 'PBKDF2_HASH_PLACEHOLDER_Finance@2025!', 'Finance Admin', 'admin', 'finance', 'secret', 'active');

-- Student 1: Student2 / Student@2025!
INSERT INTO users (id, username, email, password_encrypted, full_name, role, department, clearance, enrollment_status) VALUES
('st-001', 'Student2', 'samaa@student.examguard.edu', 'PBKDF2_HASH_PLACEHOLDER_Student@2025!', 'Samaa Mohamed', 'student', 'Computer Science', 'standard', 'active');

-- Demo Student: Student / Dem@1000335
INSERT INTO users (id, username, email, password_encrypted, full_name, role, department, clearance, enrollment_status) VALUES
('demo-user-id', 'Student', 'demo@examguard.edu', 'PBKDF2_HASH_PLACEHOLDER_Dem@1000335', 'Demo Student Account', 'student', 'Quality Assurance', 'standard', 'active');

-- ─── EXAMS ───

-- Exam 1: Secure Coding Foundations
INSERT INTO exams (id, title, description, course_name, room_code, instructor_id, duration_minutes, total_marks, start_time, end_time, is_published, status, anti_cheat_enabled, requires_camera, requires_microphone) VALUES
('ex-demo-001', 'Secure Coding Foundations', 'Introductory exam covering standard practices', 'CSE243', 'DEMO11', 'ad-001', 60, 15, '2025-01-01 08:00:00', '2027-12-31 23:59:59', 1, 'published', 1, 0, 0);

-- Exam 2: Advanced Cryptography Exam
INSERT INTO exams (id, title, description, course_name, room_code, instructor_id, duration_minutes, total_marks, start_time, end_time, is_published, status, anti_cheat_enabled, requires_camera, requires_microphone) VALUES
('ex-demo-002', 'Advanced Cryptography Exam', 'Testing AES, RSA and PKI concepts', 'CSE400', 'CRYPTO', 'ad-001', 120, 15, '2025-01-01 08:00:00', '2027-12-31 23:59:59', 1, 'published', 1, 0, 0);

-- Exam 3: Fast Demo: ABC Quiz
INSERT INTO exams (id, title, description, course_name, room_code, instructor_id, duration_minutes, total_marks, start_time, end_time, is_published, status, anti_cheat_enabled, requires_camera, requires_microphone) VALUES
('ex-demo-003', 'Fast Demo: ABC Quiz', 'Test for auto-grading logic.', 'ENG101', 'ABC123', 'ad-001', 5, 30, '2025-01-01 00:00:00', '2027-12-31 23:59:59', 1, 'published', 1, 0, 0);

-- ─── QUESTIONS ───

-- Exam 1 Questions
INSERT INTO questions (id, exam_id, question_text, question_type, options, correct_answer, marks, order_index) VALUES
('ex1-q1', 'ex-demo-001', 'What is 1 + 1?', 'mcq', '["1", "2", "3", "4"]', '2', 10, 1),
('ex1-q2', 'ex-demo-001', 'The Earth is flat.', 'true_false', '["True", "False"]', 'False', 10, 2),
('ex1-q3', 'ex-demo-001', 'Briefly explain why security is important in online exams.', 'open_ended', '[]', 'Analysis', 10, 3);

-- Exam 3 Questions (All auto-gradable)
INSERT INTO questions (id, exam_id, question_text, question_type, options, correct_answer, marks, order_index) VALUES
('ex3-q1', 'ex-demo-003', 'Which letter comes after A?', 'mcq', '["B", "C", "D", "E"]', 'B', 10, 1),
('ex3-q2', 'ex-demo-003', 'Which letter comes before Z?', 'mcq', '["X", "Y", "W", "V"]', 'Y', 10, 2),
('ex3-q3', 'ex-demo-003', 'Is "Apple" a fruit?', 'true_false', '["True", "False"]', 'True', 10, 3);

-- ─── EXAM ENROLLMENTS ───

INSERT INTO exam_enrollments (id, exam_id, student_id) VALUES
('ex-demo-001-st-001', 'ex-demo-001', 'st-001'),
('ex-demo-001-demo-user-id', 'ex-demo-001', 'demo-user-id'),
('ex-demo-002-st-001', 'ex-demo-002', 'st-001'),
('ex-demo-002-demo-user-id', 'ex-demo-002', 'demo-user-id'),
('ex-demo-003-st-001', 'ex-demo-003', 'st-001'),
('ex-demo-003-demo-user-id', 'ex-demo-003', 'demo-user-id');

-- ─── CUSTOM ROLES ───

INSERT INTO custom_roles (id, name, is_public, created_by) VALUES
('role-demo-001', 'Competition', 1, 'ad-001'),
('role-demo-002', 'Exam Committee', 0, 'ad-001');

-- ─── STUDENT GROUPS ───

INSERT INTO student_groups (id, name, description, instructor_id, max_members) VALUES
('group-demo-001', 'Group 1', 'Capstone Project Group', 'ad-001', 5),
('group-demo-002', 'Group 2', 'Capstone Project Group', 'ad-001', 5);

-- ─── USER-ROLE ASSIGNMENTS ───

INSERT INTO user_custom_roles (user_id, role_id) VALUES
('demo-user-id', 'role-demo-001');

-- ─── USER-GROUP ASSIGNMENTS ───

INSERT INTO student_group_members (user_id, group_id) VALUES
('demo-user-id', 'group-demo-001');

-- ─── INITIAL AUDIT LOG ───

INSERT INTO audit_logs (id, user_id, username, action, resource, details, severity) VALUES
('audit-init-001', 'sa-001', 'superadmin', 'SYSTEM_INIT', 'system', 'Full system initialized with 3-role architecture and groups/roles schema.', 'info');

-- ══════════════════════════════════════════════════════════════
-- DEMO CREDENTIALS
-- ══════════════════════════════════════════════════════════════
-- Super Admin : SAdmin     / SuperAdmin@2025!
-- Teacher 1   : Teacher    / Instructor@2025!
-- Teacher 2   : Teacher2   / Instructor@2025!
-- Finance     : Finance    / Finance@2025!
-- Student 1   : Student2   / Student@2025!
-- Demo Student: Student    / Dem@1000335
-- ══════════════════════════════════════════════════════════════
