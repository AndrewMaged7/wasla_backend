const { SecurityEvent } = require('../models');

// records a security event for a user (login, password change, suspension...). Never blocks the request.
function logEvent(userId, type, req, meta) {
  SecurityEvent.create({
    user: userId,
    type,
    ip: req && req.ip,
    userAgent: req && req.get ? (req.get('user-agent') || '').slice(0, 300) : undefined,
    meta,
  }).catch((err) => console.error('WARN: failed to record security event:', err.message));
}

module.exports = { logEvent };