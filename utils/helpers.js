/**
 * ExamGuard Pro — Helper Utilities
 */
const { PASSWORD_POLICY } = require('../config/security');

// Validate password against security policy
function validatePassword(password) {
  const errors = [];
  if (password.length < PASSWORD_POLICY.minLength)
    errors.push(`Password must be at least ${PASSWORD_POLICY.minLength} characters`);
  if (password.length > PASSWORD_POLICY.maxLength)
    errors.push(`Password must not exceed ${PASSWORD_POLICY.maxLength} characters`);
  if (PASSWORD_POLICY.requireUppercase && !/[A-Z]/.test(password))
    errors.push('Password must contain at least one uppercase letter');
  if (PASSWORD_POLICY.requireLowercase && !/[a-z]/.test(password))
    errors.push('Password must contain at least one lowercase letter');
  if (PASSWORD_POLICY.requireDigit && !/\d/.test(password))
    errors.push('Password must contain at least one digit');
  if (PASSWORD_POLICY.requireSpecial && !/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password))
    errors.push('Password must contain at least one special character');
  return { isValid: errors.length === 0, errors };
}

// Sanitize string input (basic XSS prevention)
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

// Format date for display
function formatDate(dateStr) {
  if (!dateStr) return 'N/A';
  const d = new Date(dateStr);
  return d.toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

// Calculate time remaining
function getTimeRemaining(endTime) {
  const now = new Date();
  const end = new Date(endTime);
  const diff = end - now;
  if (diff <= 0) return { expired: true, minutes: 0, seconds: 0 };
  return {
    expired: false,
    minutes: Math.floor(diff / 60000),
    seconds: Math.floor((diff % 60000) / 1000)
  };
}

// Generate role display name
function getRoleDisplayName(role) {
  const names = {
    'super_admin': 'Super Admin',
    'admin': 'Instructor',
    'student': 'Student'
  };
  return names[role] || role;
}

module.exports = {
  validatePassword,
  sanitizeInput,
  formatDate,
  getTimeRemaining,
  getRoleDisplayName
};
