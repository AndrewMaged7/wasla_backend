const jwt = require('jsonwebtoken');
const env = require('../config/env');
const { Session } = require('../models');
const { logEvent } = require('../utils/securityEvents');

// creates a session for the device and returns a JWT bound to it
async function createSession(user, req) {
  const body = (req && req.body) || {};
  const deviceId = typeof body.deviceId === 'string' && body.deviceId ? body.deviceId.slice(0, 100) : undefined;
  const deviceName = typeof body.deviceName === 'string' && body.deviceName ? body.deviceName.slice(0, 100) : undefined;

  const newDevice = deviceId ? !(await Session.exists({ user: user._id, deviceId })) : false;

  const session = await Session.create({
    user: user._id,
    deviceId,
    deviceName,
    userAgent: (req.get('user-agent') || '').slice(0, 300),
    ip: req.ip,
    expiresAt: new Date(Date.now() + env.SESSION_DAYS * 24 * 60 * 60 * 1000),
  });

  // if there are more devices than allowed, revoke the oldest sessions
  const active = await Session.find({ user: user._id, revokedAt: null, expiresAt: { $gt: new Date() } })
    .sort({ lastActiveAt: 1 })
    .select('_id');
  if (active.length > env.MAX_SESSIONS) {
    const extra = active.slice(0, active.length - env.MAX_SESSIONS).map((s) => s._id);
    await Session.updateMany({ _id: { $in: extra } }, { revokedAt: new Date(), revokedReason: 'max_sessions' });
  }

  logEvent(user._id, newDevice ? 'login_new_device' : 'login_success', req, { deviceName });

  return jwt.sign({ id: String(user._id), sid: String(session._id) }, env.JWT_SECRET, {
    expiresIn: `${env.SESSION_DAYS}d`,
  });
}

// signs a user out of every session (or of every session except one)
async function revokeSessions(userId, { exceptId, reason } = {}) {
  const filter = { user: userId, revokedAt: null };
  if (exceptId) filter._id = { $ne: exceptId };
  await Session.updateMany(filter, { revokedAt: new Date(), revokedReason: reason || 'revoked' });
}

module.exports = { createSession, revokeSessions };