const express = require('express');
const bcrypt = require('bcryptjs');
const env = require('../config/env');
const { OTP_EXPIRES_MS } = require('../config/constants');
const { isAdminPhone } = require('../config/admin');
const { User, Session } = require('../models');
const { normalizePhone } = require('../utils/normalization');
const { validatePassword, validateSignup } = require('../utils/validation');
const { publicUser } = require('../utils/userSerializer');
const { logEvent } = require('../utils/securityEvents');
const { sendOtp, verifyOtp } = require('../services/otp.service');
const { createSession, revokeSessions } = require('../services/session.service');
const {
  refreshStatus,
  statusBody,
  registerFailedLogin,
  lockedBody,
} = require('../services/accountStatus.service');
const { protect } = require('../middleware/auth.middleware');
const {
  signupLimiter,
  loginLimiter,
  otpVerifyLimiter,
  otpSendLimiter,
} = require('../middleware/rateLimit.middleware');

const router = express.Router();

// dummy hash compared against when the phone does not exist (keeps response time roughly constant)
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 12);

// POST /api/auth/signup
router.post('/signup', signupLimiter, async (req, res, next) => {
  try {
    const { name, password, confirmPassword, acceptTerms, acceptPrivacy, role } = req.body || {};
    const phone = normalizePhone(req.body && req.body.phone);

    const errors = validateSignup({ name, phone, password, confirmPassword, acceptTerms, acceptPrivacy, role });
    if (errors.length) {
      return res.status(400).json({ success: false, message: 'Invalid data', errors });
    }

    let user = await User.findOne({ phone });
    if (user && user.isPhoneVerified) {
      return res.status(409).json({ success: false, message: 'This phone number is already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const now = new Date();
    const legal = {
      termsAcceptedAt: now,
      termsVersion: env.TERMS_VERSION,
      privacyAcceptedAt: now,
      privacyVersion: env.PRIVACY_VERSION,
    };

    if (user) {
      // account that was never verified: update its data and send a new code
      user.name = name.trim();
      user.password = hashedPassword;
      user.role = role || 'rider';
      Object.assign(user, legal);
      await user.save();
    } else {
      user = await User.create({
        name: name.trim(),
        phone,
        password: hashedPassword,
        role: role || 'rider',
        ...legal,
      });
    }

    let result;
    try {
      result = await sendOtp(phone, 'signup');
    } catch (smsErr) {
      console.error('WARN: failed to send SMS:', smsErr.message);
      return res.status(502).json({
        success: false,
        message: 'Account created but sending the verification code failed, please request a new code',
      });
    }

    if (!result.sent) {
      return res.status(429).json({
        success: false,
        message: `Please wait ${result.retryAfter} seconds before requesting a new code`,
        retryAfter: result.retryAfter,
      });
    }

    return res.status(201).json({
      success: true,
      message: 'Account created, we sent a verification code to your phone',
      phone,
      otpExpiresInMinutes: OTP_EXPIRES_MS / 60000,
    });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(409).json({ success: false, message: 'This phone number is already registered' });
    }
    next(err);
  }
});

// POST /api/auth/verify-otp  (activates the account after signup)
router.post('/verify-otp', otpVerifyLimiter, async (req, res, next) => {
  try {
    const phone = normalizePhone(req.body && req.body.phone);
    const { code } = req.body || {};

    if (!phone || typeof code !== 'string') {
      return res.status(400).json({ success: false, message: 'Phone number and code are required' });
    }

    const ok = await verifyOtp(phone, 'signup', code);
    const user = ok ? await User.findOne({ phone }) : null;

    if (!ok || !user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired code' });
    }

    user.isPhoneVerified = true;
    // an admin phone becomes admin once it has proven ownership of the number with the OTP
    if (isAdminPhone(user.phone)) user.role = 'admin';
    await user.save();

    await refreshStatus(user);
    if (user.status !== 'active') return res.status(403).json(statusBody(user));

    const token = await createSession(user, req);

    return res.json({
      success: true,
      message: 'Account verified successfully',
      token,
      user: publicUser(user),
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/resend-otp  (resends the verification code)
router.post('/resend-otp', otpSendLimiter, async (req, res, next) => {
  const genericResponse = {
    success: true,
    message: 'If this number needs verification, a new code has been sent',
  };

  try {
    const phone = normalizePhone(req.body && req.body.phone);
    if (!phone) {
      return res.status(400).json({ success: false, message: 'Invalid phone number' });
    }

    const user = await User.findOne({ phone });
    if (user && !user.isPhoneVerified) {
      try {
        await sendOtp(phone, 'signup');
      } catch (smsErr) {
        console.error('WARN: failed to send SMS:', smsErr.message);
      }
    }

    return res.json(genericResponse);
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/login  (you may send deviceId and deviceName so the device shows in the devices list)
router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const { password } = req.body || {};
    const phone = normalizePhone(req.body && req.body.phone);

    if (!phone || typeof password !== 'string' || !password) {
      return res.status(400).json({ success: false, message: 'Phone number and password are required' });
    }

    const user = await User.findOne({ phone }).select('+password');

    // while the account is temporarily locked we do not even check the password
    if (user && user.lockUntil && user.lockUntil > new Date()) {
      return res.status(429).json(lockedBody(user));
    }

    // always compare, and return the same message whether the phone or the password is wrong
    const isMatch = await bcrypt.compare(password, user ? user.password : DUMMY_HASH);
    if (!user || !isMatch) {
      if (user) await registerFailedLogin(user._id, req);
      return res.status(401).json({ success: false, message: 'Incorrect phone number or password' });
    }

    await refreshStatus(user);
    if (user.status !== 'active') {
      logEvent(user._id, 'login_blocked', req, { status: user.status });
      return res.status(403).json(statusBody(user));
    }

    if (!user.isPhoneVerified) {
      try {
        await sendOtp(phone, 'signup');
      } catch (smsErr) {
        console.error('WARN: failed to send SMS:', smsErr.message);
      }
      return res.status(403).json({
        success: false,
        needsVerification: true,
        message: 'You must verify your phone number first, we sent you a verification code',
      });
    }

    await User.updateOne(
      { _id: user._id },
      { $set: { failedLoginAttempts: 0, lastLoginAt: new Date() }, $unset: { lockUntil: 1 } }
    );

    const token = await createSession(user, req);

    return res.json({
      success: true,
      message: 'Logged in successfully',
      token,
      user: publicUser(user),
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/logout  (ends the current device session only)
router.post('/logout', protect, async (req, res, next) => {
  try {
    await Session.updateOne({ _id: req.session._id }, { revokedAt: new Date(), revokedReason: 'logout' });
    logEvent(req.user._id, 'logout', req);
    res.json({ success: true, message: 'Logged out' });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/forgot-password  (sends an OTP to the phone)
router.post('/forgot-password', otpSendLimiter, async (req, res, next) => {
  // always the same response so nobody can find out who is registered
  const genericResponse = {
    success: true,
    message: 'If this number is registered, a password reset code has been sent',
  };

  try {
    const phone = normalizePhone(req.body && req.body.phone);
    if (!phone) {
      return res.status(400).json({ success: false, message: 'Invalid phone number' });
    }

    const user = await User.findOne({ phone });
    if (user && user.isPhoneVerified) {
      try {
        await sendOtp(phone, 'reset');
      } catch (smsErr) {
        console.error('WARN: failed to send SMS:', smsErr.message);
      }
    }

    return res.json(genericResponse);
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/reset-password  (phone + code + new password)
router.post('/reset-password', otpVerifyLimiter, async (req, res, next) => {
  try {
    const { code, password, confirmPassword } = req.body || {};
    const phone = normalizePhone(req.body && req.body.phone);

    if (!phone || typeof code !== 'string') {
      return res.status(400).json({ success: false, message: 'Phone number and code are required' });
    }

    const pwErrors = validatePassword(password, confirmPassword);
    if (pwErrors.length) {
      return res.status(400).json({ success: false, message: 'Invalid data', errors: pwErrors });
    }

    const ok = await verifyOtp(phone, 'reset', code);
    const user = ok ? await User.findOne({ phone }) : null;

    if (!ok || !user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired code' });
    }

    const hashed = await bcrypt.hash(password, 12);
    // the owner proved they own the number: clear the temporary lock and revoke all old sessions
    await User.updateOne(
      { _id: user._id },
      { $set: { password: hashed, failedLoginAttempts: 0 }, $unset: { lockUntil: 1 } }
    );
    await revokeSessions(user._id, { reason: 'password_reset' });
    logEvent(user._id, 'password_reset', req);

    await refreshStatus(user);
    if (user.status !== 'active') {
      // the password was changed but the account is still blocked, so no token is issued
      return res.json({
        success: true,
        message: 'Password changed successfully, but your account is still restricted',
        code: statusBody(user).code,
      });
    }

    const token = await createSession(user, req);

    return res.json({
      success: true,
      message: 'Password changed successfully',
      token,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;