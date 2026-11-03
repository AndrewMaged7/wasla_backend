const express = require('express');
const { AVATAR_DIR } = require('../config/constants');
const { User } = require('../models');
const HttpError = require('../utils/HttpError');
const { normalizePhone, normalizeEmail } = require('../utils/normalization');
const { publicUser, photoUrl } = require('../utils/userSerializer');
const { logEvent } = require('../utils/securityEvents');
const { saveImage, removeFile } = require('../utils/imageFiles');
const { sendOtp, verifyOtp } = require('../services/otp.service');
const { revokeSessions } = require('../services/session.service');
const { sendSms, sendEmail } = require('../services/messaging.service');
const { protect, reauth } = require('../middleware/auth.middleware');
const { uploadAvatar } = require('../middleware/upload.middleware');
const {
  sensitiveLimiter,
  otpVerifyLimiter,
  uploadLimiter,
} = require('../middleware/rateLimit.middleware');

const router = express.Router();

// GET /api/profile
router.get('/', protect, (req, res) => {
  res.json({ success: true, user: publicUser(req.user) });
});

// PATCH /api/profile  (name / gender / date of birth)
router.patch('/', protect, async (req, res, next) => {
  try {
    const { name, gender, dateOfBirth } = req.body || {};
    const update = {};

    if (name !== undefined) {
      if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 50) {
        throw new HttpError(400, 'Name must be between 2 and 50 characters');
      }
      update.name = name.trim();
    }
    if (gender !== undefined) {
      if (!['male', 'female'].includes(gender)) {
        throw new HttpError(400, 'Gender must be male or female');
      }
      update.gender = gender;
    }
    if (dateOfBirth !== undefined) {
      const d = typeof dateOfBirth === 'string' ? new Date(dateOfBirth) : null;
      if (!d || isNaN(d.getTime()) || d > new Date() || d < new Date('1900-01-01')) {
        throw new HttpError(400, 'Invalid date of birth');
      }
      update.dateOfBirth = d;
    }

    if (!Object.keys(update).length) {
      throw new HttpError(400, 'Nothing to update');
    }

    const user = await User.updateAndGet(req.user._id, { $set: update });
    logEvent(user._id, 'profile_updated', req, { fields: Object.keys(update) });

    res.json({ success: true, message: 'Profile updated', user: publicUser(user) });
  } catch (err) {
    next(err);
  }
});

// PUT /api/profile/photo  (multipart/form-data - the field name is "photo")
router.put('/photo', protect, uploadLimiter, uploadAvatar.single('photo'), async (req, res, next) => {
  try {
    if (!req.file) throw new HttpError(400, 'Photo is required (field name: photo)');

    const filename = await saveImage(AVATAR_DIR, req.file);
    const oldPhoto = req.user.photo;

    const user = await User.updateAndGet(req.user._id, { $set: { photo: filename } });
    removeFile(AVATAR_DIR, oldPhoto);

    res.json({ success: true, message: 'Photo updated', photoUrl: photoUrl(user) });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/profile/photo
router.delete('/photo', protect, async (req, res, next) => {
  try {
    const oldPhoto = req.user.photo;
    await User.updateOne({ _id: req.user._id }, { $unset: { photo: 1 } });
    removeFile(AVATAR_DIR, oldPhoto);
    res.json({ success: true, message: 'Photo removed' });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/profile/settings  (language + notifications)
router.patch('/settings', protect, async (req, res, next) => {
  try {
    const { language, notifications } = req.body || {};
    const update = {};

    if (language !== undefined) {
      if (!['ar', 'en'].includes(language)) throw new HttpError(400, 'Language must be ar or en');
      update['settings.language'] = language;
    }

    if (notifications !== undefined) {
      if (!notifications || typeof notifications !== 'object' || Array.isArray(notifications)) {
        throw new HttpError(400, 'Invalid notification settings');
      }
      for (const key of ['push', 'sms', 'email', 'promotions']) {
        if (notifications[key] !== undefined) {
          if (typeof notifications[key] !== 'boolean') {
            throw new HttpError(400, `${key} must be true or false`);
          }
          update[`settings.notifications.${key}`] = notifications[key];
        }
      }
    }

    if (!Object.keys(update).length) throw new HttpError(400, 'No settings to update');

    const user = await User.updateAndGet(req.user._id, { $set: update });
    res.json({ success: true, message: 'Settings updated', settings: publicUser(user).settings });
  } catch (err) {
    next(err);
  }
});

// POST /api/profile/phone/request  { newPhone, password }  -> sends an OTP to the new number
router.post('/phone/request', sensitiveLimiter, protect, reauth('password'), async (req, res, next) => {
  try {
    const newPhone = normalizePhone(req.body && req.body.newPhone);
    if (!newPhone) throw new HttpError(400, 'Invalid new phone number');
    if (newPhone === req.user.phone) throw new HttpError(400, 'This is already your current number');

    const taken = await User.exists({ phone: newPhone, isPhoneVerified: true });
    if (taken) throw new HttpError(409, 'This phone number is used by another account');

    let result;
    try {
      result = await sendOtp(newPhone, `change_phone:${req.user._id}`);
    } catch (smsErr) {
      console.error('WARN: failed to send SMS:', smsErr.message);
      throw new HttpError(502, 'Failed to send the verification code, please try again');
    }
    if (!result.sent) {
      throw new HttpError(429, `Please wait ${result.retryAfter} seconds before requesting a new code`);
    }

    await User.updateOne({ _id: req.user._id }, { $set: { pendingPhone: newPhone } });

    res.json({ success: true, message: 'We sent a verification code to the new number', newPhone });
  } catch (err) {
    next(err);
  }
});

// POST /api/profile/phone/verify  { code }
router.post('/phone/verify', otpVerifyLimiter, protect, async (req, res, next) => {
  try {
    const newPhone = req.user.pendingPhone;
    if (!newPhone) throw new HttpError(400, 'There is no pending phone change');

    const ok = await verifyOtp(newPhone, `change_phone:${req.user._id}`, (req.body || {}).code);
    if (!ok) throw new HttpError(400, 'Invalid or expired code');

    // remove a stale, never-verified account on the same number (the real owner just proved ownership)
    await User.deleteOne({ phone: newPhone, isPhoneVerified: false, _id: { $ne: req.user._id } });

    const oldPhone = req.user.phone;
    try {
      await User.updateOne({ _id: req.user._id }, { $set: { phone: newPhone }, $unset: { pendingPhone: 1 } });
    } catch (e) {
      if (e && e.code === 11000) throw new HttpError(409, 'This phone number is used by another account');
      throw e;
    }

    // the phone is the login identifier, so all other devices are signed out
    await revokeSessions(req.user._id, { exceptId: req.session._id, reason: 'phone_changed' });
    logEvent(req.user._id, 'phone_changed', req, { from: oldPhone, to: newPhone });

    // alert the old number (failure here is not a problem)
    sendSms(oldPhone, 'The phone number on your account was changed. If this was not you, contact support immediately.').catch(() => {});

    res.json({ success: true, message: 'Phone number changed', phone: newPhone });
  } catch (err) {
    next(err);
  }
});

// POST /api/profile/email/request  { newEmail, password }  -> sends an OTP to the email
router.post('/email/request', sensitiveLimiter, protect, reauth('password'), async (req, res, next) => {
  try {
    const newEmail = normalizeEmail(req.body && req.body.newEmail);
    if (!newEmail) throw new HttpError(400, 'Invalid email address');
    if (newEmail === req.user.email) throw new HttpError(400, 'This is already your current email');

    const taken = await User.exists({ email: newEmail });
    if (taken) throw new HttpError(409, 'This email is used by another account');

    let result;
    try {
      result = await sendOtp(newEmail, `change_email:${req.user._id}`);
    } catch (mailErr) {
      console.error('WARN: failed to send email:', mailErr.message);
      throw new HttpError(502, 'Failed to send the verification code, please try again');
    }
    if (!result.sent) {
      throw new HttpError(429, `Please wait ${result.retryAfter} seconds before requesting a new code`);
    }

    await User.updateOne({ _id: req.user._id }, { $set: { pendingEmail: newEmail } });

    res.json({ success: true, message: 'We sent a verification code to your email', newEmail });
  } catch (err) {
    next(err);
  }
});

// POST /api/profile/email/verify  { code }
router.post('/email/verify', otpVerifyLimiter, protect, async (req, res, next) => {
  try {
    const newEmail = req.user.pendingEmail;
    if (!newEmail) throw new HttpError(400, 'There is no pending email change');

    const ok = await verifyOtp(newEmail, `change_email:${req.user._id}`, (req.body || {}).code);
    if (!ok) throw new HttpError(400, 'Invalid or expired code');

    const oldEmail = req.user.email;
    try {
      await User.updateOne({ _id: req.user._id }, { $set: { email: newEmail }, $unset: { pendingEmail: 1 } });
    } catch (e) {
      if (e && e.code === 11000) throw new HttpError(409, 'This email is used by another account');
      throw e;
    }

    logEvent(req.user._id, 'email_changed', req, { from: oldEmail || null, to: newEmail });

    // alert the old email if there was one
    if (oldEmail) {
      sendEmail(
        oldEmail,
        'The email on your account was changed',
        'The email address on your account was changed. If this was not you, contact support immediately.'
      ).catch(() => {});
    }

    res.json({ success: true, message: 'Email changed', email: newEmail });
  } catch (err) {
    next(err);
  }
});

module.exports = router;