const { MAX_FAILED_LOGINS, LOCK_MS } = require('../config/constants');
const { User } = require('../models');
const { logEvent } = require('../utils/securityEvents');

// when a temporary suspension has ended, the account is automatically set back to active
async function refreshStatus(user) {
  if (user.status === 'suspended' && user.suspendedUntil && user.suspendedUntil <= new Date()) {
    await User.updateOne(
      { _id: user._id },
      { $set: { status: 'active', statusChangedAt: new Date() }, $unset: { suspendedUntil: 1, statusReason: 1 } }
    );
    user.status = 'active';
    user.suspendedUntil = undefined;
    logEvent(user._id, 'suspension_expired', null);
  }
}

// the response sent to a suspended or banned user (never contains the internal reason)
function statusBody(user) {
  if (user.status === 'banned') {
    return {
      success: false,
      code: 'ACCOUNT_BANNED',
      message: 'Your account has been permanently banned. If you think this is a mistake, please contact support',
    };
  }
  return {
    success: false,
    code: 'ACCOUNT_SUSPENDED',
    message: 'Your account is temporarily suspended. Please contact support if you need help',
    suspendedUntil: user.suspendedUntil || null,
  };
}

// counts a failed password attempt and locks the account after too many of them
async function registerFailedLogin(userId, req) {
  const u = await User.updateAndGet(userId, { $inc: { failedLoginAttempts: 1 } });
  logEvent(userId, 'login_failed', req);

  if (u && u.failedLoginAttempts >= MAX_FAILED_LOGINS) {
    await User.updateOne(
      { _id: userId },
      {
        $set: {
          lockUntil: new Date(Date.now() + LOCK_MS),
          failedLoginAttempts: 0,
          flagged: true,
          flagReason: 'Repeated failed login attempts',
        },
      }
    );
    logEvent(userId, 'account_locked', req);
  }
}

function lockedBody(user) {
  const mins = Math.ceil((user.lockUntil.getTime() - Date.now()) / 60000);
  return {
    success: false,
    code: 'ACCOUNT_LOCKED',
    message: `Account temporarily locked due to too many failed attempts. Try again in ${mins} minute(s)`,
  };
}

module.exports = { refreshStatus, statusBody, registerFailedLogin, lockedBody };