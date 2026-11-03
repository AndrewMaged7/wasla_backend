const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { AVATAR_DIR, PRIVATE_DIR } = require('../config/constants');
const { User, Session, SecurityEvent } = require('../models');
const HttpError = require('../utils/HttpError');
const { OBJECT_ID_REGEX } = require('../utils/regex');
const { validatePassword } = require('../utils/validation');
const { logEvent } = require('../utils/securityEvents');
const { detectImage, saveImage, removeFile, removeIdentityDocs } = require('../utils/imageFiles');
const { revokeSessions } = require('../services/session.service');
const { protect, reauth } = require('../middleware/auth.middleware');
const { uploadIdDocs } = require('../middleware/upload.middleware');
const { sensitiveLimiter, identityLimiter } = require('../middleware/rateLimit.middleware');

const router = express.Router();

// POST /api/account/change-password  { currentPassword, newPassword, confirmPassword }
router.post(
  '/change-password',
  sensitiveLimiter,
  protect,
  reauth('currentPassword'),
  async (req, res, next) => {
    try {
      const { currentPassword, newPassword, confirmPassword } = req.body || {};

      const errors = validatePassword(newPassword, confirmPassword);
      if (errors.length) {
        return res.status(400).json({ success: false, message: 'Invalid data', errors });
      }
      if (newPassword === currentPassword) {
        throw new HttpError(400, 'The new password must be different from the current one');
      }

      const hashed = await bcrypt.hash(newPassword, 12);
      await User.updateOne({ _id: req.user._id }, { $set: { password: hashed } });

      // sign out every other device and keep the current one
      await revokeSessions(req.user._id, { exceptId: req.session._id, reason: 'password_changed' });
      logEvent(req.user._id, 'password_changed', req);

      res.json({ success: true, message: 'Password changed, and all other devices were signed out' });
    } catch (err) {
      next(err);
    }
  }
);

// GET /api/account/sessions  (signed-in devices)
router.get('/sessions', protect, async (req, res, next) => {
  try {
    const sessions = await Session.find({
      user: req.user._id,
      revokedAt: null,
      expiresAt: { $gt: new Date() },
    }).sort({ lastActiveAt: -1 });

    res.json({
      success: true,
      sessions: sessions.map((s) => ({
        id: s._id,
        deviceName: s.deviceName || null,
        userAgent: s.userAgent || null,
        ip: s.ip || null,
        createdAt: s.createdAt,
        lastActiveAt: s.lastActiveAt,
        current: String(s._id) === String(req.session._id),
      })),
    });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/account/sessions  (sign out of all other devices)
router.delete('/sessions', protect, async (req, res, next) => {
  try {
    await revokeSessions(req.user._id, { exceptId: req.session._id, reason: 'logout_others' });
    logEvent(req.user._id, 'sessions_revoked_all', req);
    res.json({ success: true, message: 'Signed out of all other devices' });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/account/sessions/:id  (sign out a specific device)
router.delete('/sessions/:id', protect, async (req, res, next) => {
  try {
    if (!OBJECT_ID_REGEX.test(req.params.id)) throw new HttpError(400, 'Invalid session id');

    const result = await Session.updateOne(
      { _id: req.params.id, user: req.user._id, revokedAt: null },
      { revokedAt: new Date(), revokedReason: 'revoked_by_user' }
    );
    if (!result.matchedCount) throw new HttpError(404, 'Session not found');

    logEvent(req.user._id, 'session_revoked', req, { sessionId: req.params.id });
    res.json({ success: true, message: 'Device signed out' });
  } catch (err) {
    next(err);
  }
});

// GET /api/account/security-events  (recent activity on your account)
router.get('/security-events', protect, async (req, res, next) => {
  try {
    const events = await SecurityEvent.find({ user: req.user._id }).sort({ createdAt: -1 }).limit(50);
    res.json({
      success: true,
      events: events.map((e) => ({ type: e.type, ip: e.ip || null, userAgent: e.userAgent || null, createdAt: e.createdAt })),
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/account/identity  (identity verification status)
router.get('/identity', protect, (req, res) => {
  const id = req.user.identity || {};
  res.json({
    success: true,
    status: id.status || 'none',
    submittedAt: id.submittedAt || null,
    reviewedAt: id.reviewedAt || null,
    rejectionReason: id.status === 'rejected' ? id.rejectionReason || null : null,
  });
});

// POST /api/account/identity  (multipart/form-data: idFront, idBack, selfie)
router.post(
  '/identity',
  protect,
  identityLimiter,
  uploadIdDocs.fields([
    { name: 'idFront', maxCount: 1 },
    { name: 'idBack', maxCount: 1 },
    { name: 'selfie', maxCount: 1 },
  ]),
  async (req, res, next) => {
    try {
      const status = (req.user.identity && req.user.identity.status) || 'none';
      if (status === 'approved') throw new HttpError(409, 'Your identity is already verified');
      if (status === 'pending') throw new HttpError(409, 'Your request is already under review');

      const files = req.files || {};
      const front = files.idFront && files.idFront[0];
      const back = files.idBack && files.idBack[0];
      const selfie = files.selfie && files.selfie[0];
      if (!front || !back || !selfie) {
        throw new HttpError(400, 'You must upload 3 images: idFront, idBack and selfie');
      }

      // validate all three before saving any of them, so a bad file never leaves orphan files behind
      for (const f of [front, back, selfie]) {
        if (!detectImage(f.buffer)) throw new HttpError(400, 'All files must be images (JPG, PNG or WEBP)');
      }

      const docs = {
        front: await saveImage(PRIVATE_DIR, front),
        back: await saveImage(PRIVATE_DIR, back),
        selfie: await saveImage(PRIVATE_DIR, selfie),
      };

      const oldIdentity = req.user.identity;
      await User.updateOne(
        { _id: req.user._id },
        {
          $set: { 'identity.status': 'pending', 'identity.submittedAt': new Date(), 'identity.docs': docs },
          $unset: { 'identity.rejectionReason': 1, 'identity.reviewedAt': 1, 'identity.reviewedBy': 1 },
        }
      );
      removeIdentityDocs(oldIdentity); // documents of the previous rejected attempt

      logEvent(req.user._id, 'identity_submitted', req);

      res.status(201).json({ success: true, message: 'Documents received and will be reviewed', status: 'pending' });
    } catch (err) {
      next(err);
    }
  }
);

// POST /api/account/delete  { password }  (delete the account)
router.post('/delete', sensitiveLimiter, protect, reauth('password'), async (req, res, next) => {
  try {
    const id = req.user._id;
    const oldPhoto = req.user.photo;
    const oldIdentity = req.user.identity;

    // personal data is wiped, the account stays as an anonymous record
    await User.updateOne(
      { _id: id },
      {
        $set: {
          status: 'deleted',
          statusChangedAt: new Date(),
          name: 'Deleted user',
          phone: `deleted:${id}`,
          password: await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 10),
          'identity.status': 'none',
          flagged: false,
        },
        $unset: {
          email: 1,
          photo: 1,
          gender: 1,
          dateOfBirth: 1,
          pendingPhone: 1,
          pendingEmail: 1,
          'identity.docs': 1,
        },
      }
    );
    removeFile(AVATAR_DIR, oldPhoto);
    removeIdentityDocs(oldIdentity);

    await revokeSessions(id, { reason: 'account_deleted' });
    logEvent(id, 'account_deleted', req);

    res.json({ success: true, message: 'Account deleted' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;