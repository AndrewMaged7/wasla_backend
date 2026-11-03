const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const env = require('../config/env');
const { User, Session } = require('../models');
const { OBJECT_ID_REGEX } = require('../utils/regex');
const {
  refreshStatus,
  statusBody,
  registerFailedLogin,
  lockedBody,
} = require('../services/accountStatus.service');

// checks the JWT + that the session is still alive + the account status
async function protect(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.split(' ')[1] : null;
    if (!token) {
      return res.status(401).json({ success: false, message: 'Authentication required' });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, env.JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }

    if (!OBJECT_ID_REGEX.test(String(decoded.id)) || !OBJECT_ID_REGEX.test(String(decoded.sid))) {
      return res.status(401).json({ success: false, message: 'Please log in again' });
    }

    const session = await Session.findOne({
      _id: decoded.sid,
      user: decoded.id,
      revokedAt: null,
      expiresAt: { $gt: new Date() },
    });
    if (!session) {
      return res.status(401).json({ success: false, message: 'Session expired, please log in again' });
    }

    const user = await User.findById(decoded.id);
    if (!user || !user.isPhoneVerified || user.status === 'deleted') {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    await refreshStatus(user);
    if (user.status !== 'active') {
      return res.status(403).json(statusBody(user));
    }

    // update last activity (at most once every 5 minutes to avoid hammering the database)
    if (Date.now() - session.lastActiveAt.getTime() > 5 * 60 * 1000) {
      await Session.updateOne({ _id: session._id }, { lastActiveAt: new Date() });
    }

    req.user = user;
    req.session = session;
    next();
  } catch (err) {
    next(err);
  }
}

// allows only the given roles, e.g. requireRole('admin')
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: 'You are not allowed to perform this action' });
    }
    next();
  };
}

// re-checks the password before sensitive actions (change phone / email / password, delete account)
function reauth(field = 'password') {
  return async (req, res, next) => {
    try {
      const plain = (req.body || {})[field];
      if (typeof plain !== 'string' || !plain) {
        return res.status(400).json({ success: false, message: 'You must confirm your current password' });
      }

      const user = await User.findById(req.user._id).select('+password');

      if (user.lockUntil && user.lockUntil > new Date()) {
        return res.status(429).json(lockedBody(user));
      }

      const ok = await bcrypt.compare(plain, user.password);
      if (!ok) {
        await registerFailedLogin(user._id, req);
        return res.status(401).json({ success: false, message: 'Incorrect password' });
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}

module.exports = { protect, requireRole, reauth };