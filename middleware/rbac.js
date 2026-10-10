/**
 * ExamGuard Pro — Role-Based Access Control (RBAC) Middleware
 * Enforces role hierarchy: super_admin > admin > student
 * STRIDE: Elevation of Privilege mitigation
 */
const { ROLES } = require('../config/security');

// Role hierarchy for permission inheritance
const ROLE_HIERARCHY = {
  [ROLES.SUPER_ADMIN]: 3,
  [ROLES.ADMIN]: 2,
  [ROLES.STUDENT]: 1
};

/**
 * Restrict access to specific roles
 * @param  {...string} allowedRoles - Roles permitted to access the route
 */
function authorize(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      // Log unauthorized access attempt
      const { getDatabase } = require('../config/database');
      const { v4: uuidv4 } = require('uuid');
      const db = getDatabase();
      db.prepare(
        'INSERT INTO audit_logs (id, user_id, username, action, resource, details, ip_address, severity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).run(
        uuidv4(), req.user.id, req.user.username,
        'UNAUTHORIZED_ACCESS_ATTEMPT', req.originalUrl,
        `User with role '${req.user.role}' attempted to access route requiring [${allowedRoles.join(', ')}]`,
        req.ip, 'warning'
      );

      if (req.xhr || req.path.startsWith('/api/')) {
        return res.status(403).json({ error: 'Access denied. Insufficient privileges.' });
      }
      return res.status(403).render('error', {
        title: 'Access Denied',
        message: 'You do not have permission to access this resource.',
        code: 403
      });
    }

    next();
  };
}

/**
 * Require minimum role level
 */
function requireMinRole(minRole) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const userLevel = ROLE_HIERARCHY[req.user.role] || 0;
    const requiredLevel = ROLE_HIERARCHY[minRole] || 0;

    if (userLevel < requiredLevel) {
      return res.status(403).json({ error: 'Insufficient role privileges' });
    }

    next();
  };
}

module.exports = { authorize, requireMinRole, ROLE_HIERARCHY };
