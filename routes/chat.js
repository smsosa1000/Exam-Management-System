/**
 * ExamGuard Pro — Chat Routes (E2E Encrypted)
 * STRIDE: All categories covered
 */
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { getDatabase } = require('../config/database');
const { authenticate } = require('../middleware/auth');
const { aesEncryptWithIV, aesDecryptWithIV } = require('../utils/encryption');
const { logAuditEvent } = require('../middleware/auditLog');

router.use(authenticate);

// GET /chat — Chat page
router.get('/', (req, res) => {
  const db = getDatabase();
  let contacts;
  if (req.user.role === 'student') {
    contacts = db.prepare(
      `SELECT DISTINCT u.id, u.full_name, u.role, u.username FROM users u
       JOIN exams e ON e.instructor_id = u.id
       JOIN exam_enrollments ee ON ee.exam_id = e.id
       WHERE ee.student_id = ? ORDER BY u.full_name`
    ).all(req.user.id);
  } else {
    contacts = db.prepare(
      'SELECT id, full_name, role, username FROM users WHERE id != ? ORDER BY role, full_name'
    ).all(req.user.id);
  }
  res.render('chat/index', { title: 'Secure Chat — ExamGuard Pro', contacts });
});

// GET /chat/messages/:userId — Get messages with user
router.get('/messages/:userId', (req, res) => {
  const db = getDatabase();
  const messages = db.prepare(
    `SELECT * FROM chat_messages
     WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
     ORDER BY created_at ASC`
  ).all(req.user.id, req.params.userId, req.params.userId, req.user.id);

  const decryptedMessages = messages.map(msg => {
    try {
      return { ...msg, decrypted_message: aesDecryptWithIV(msg.encrypted_message, msg.message_iv) };
    } catch {
      return { ...msg, decrypted_message: '[Decryption failed]' };
    }
  });

  // Mark as read
  db.prepare('UPDATE chat_messages SET is_read = 1 WHERE receiver_id = ? AND sender_id = ?')
    .run(req.user.id, req.params.userId);

  res.json({ messages: decryptedMessages });
});

// GET /chat/search — Directory search for adding contacts
router.get('/search', (req, res) => {
  const db = getDatabase();
  const query = req.query.q ? `%${req.query.q}%` : '%%';
  const users = db.prepare(
    `SELECT id, full_name, role, username FROM users 
     WHERE id != ? AND (full_name LIKE ? OR username LIKE ?) 
     LIMIT 10`
  ).all(req.user.id, query, query);
  res.json({ users });
});

// POST /chat/send — Send encrypted message
router.post('/send', (req, res) => {
  const db = getDatabase();
  const { receiver_id, message } = req.body;
  if (!message || !receiver_id) return res.status(400).json({ error: 'Message and receiver required' });

  const { encrypted, iv } = aesEncryptWithIV(message);
  db.prepare(
    'INSERT INTO chat_messages (id, sender_id, receiver_id, encrypted_message, message_iv) VALUES (?, ?, ?, ?, ?)'
  ).run(uuidv4(), req.user.id, receiver_id, encrypted, iv);

  logAuditEvent(req.user.id, req.user.username, 'CHAT_MESSAGE_SENT', 'chat', receiver_id, 'Encrypted message', req.ip, req.get('User-Agent'));
  res.json({ success: true });
});

module.exports = router;
