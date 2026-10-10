/**
 * ExamGuard Pro — Database Configuration
 * SQLite3 connection via better-sqlite3
 * Enforces WAL mode and foreign keys for integrity
 */
const Database = require('better-sqlite3');
const path = require('path');
require('dotenv').config();

const DB_PATH = path.resolve(__dirname, '..', process.env.DB_PATH || './database/examguard.db');

let db;

function getDatabase() {
  if (!db) {
    db = new Database(DB_PATH);
    // Enable WAL mode for better concurrent read performance
    db.pragma('journal_mode = WAL');
    // Enforce foreign key constraints
    db.pragma('foreign_keys = ON');
  }
  return db;
}

function closeDatabase() {
  if (db) {
    db.close();
    db = null;
  }
}

module.exports = { getDatabase, closeDatabase };
