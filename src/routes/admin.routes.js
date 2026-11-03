const express = require('express');
const path = require('path');
const { PRIVATE_DIR } = require('../config/constants');
const { User, Session, SecurityEvent } = require('../models');
const HttpError = require('../utils/HttpError');
const { OBJECT_ID_REGEX, escapeRegex } = require('../utils/regex');
const { requireReason } = require('../utils/validation');
const { adminUserView } = require('../utils/userSerializer');
const { logEvent } = require('../utils/securityEvents');
const { revokeSessions } = require('../services/session.service');
const { protect, requireRole } = require('../middleware/auth.middleware');

const router = express.Router();

// every route in this file is for admins only
router.use(protect, requireRole('admin'));

// loads the user from :id. With allowAdmin: false it refuses admins and the caller themselves
async function getTarget(req, { allowAdmin = true } = {}) {
  if (!OBJECT_ID_REGEX.test(req.params.id)) throw new HttpError(400, 'Invalid user id');
  const target = await User.findById(req.params.id);
  if (!target) throw new HttpError(404, 'User not found');
  if (!allowAdmin && (target.role === 'admin' || String(target._id) === String(req.user._id))) {
    throw new HttpError(403, 'You cannot perform this action on an admin or on yourself');
  }
  return target;
}

// GET /api/admin/users?status=&role=&flagged=true&q=010&identity=pending&page=1&limit=20
router.get('/users', async (req, res, next) => {
  try {
    const { status, role, flagged, q, identity } = req.query;
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 50);

    const filter = {};
    if (typeof status === 'string' && ['active', 'suspended', 'banned', 'deleted'].includes(status)) filter.status = status;
    if (typeof role === 'string' && ['rider', 'driver', 'admin'].includes(role)) filter.role = role;
    if (flagged === 'true') filter.flagged = true;
    if (typeof identity === 'string' && ['none', 'pending', 'approved', 'rejected'].includes(identity)) {
      filter['identity.status'] = identity;
    }
    if (typeof q === 'string' && q.trim()) filter.phone = new RegExp(escapeRegex(q.trim()));

    const [users, total] = await Promise.all([
      User.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit),
      User.countDocuments(filter),
    ]);

    res.json({ success: true, page, limit, total, users: users.map(adminUserView) });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/users/:id
router.get('/users/:id', async (req, res, next) => {
  try {
    const target = await getTarget(req);
    const activeSessions = await Session.countDocuments({
      user: target._id,
      revokedAt: null,
      expiresAt: { $gt: new Date() },
    });
    res.json({ success: true, user: { ...adminUserView(target), activeSessions } });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/users/:id/security-events
router.get('/users/:id/security-events', async (req, res, next) => {
  try {
    const target = await getTarget(req);
    const events = await SecurityEvent.find({ user: target._id }).sort({ createdAt: -1 }).limit(100);
    res.json({ success: true, events });
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/users/:id/suspend  { reason, days? }  (without days = suspended until an admin reinstates it)
router.post('/users/:id/suspend', async (req, res, next) => {
  try {
    const target = await getTarget(req, { allowAdmin: false });
    const { days } = req.body || {};
    const reason = requireReason((req.body || {}).reason);

    const set = { status: 'suspended', statusReason: reason, statusChangedAt: new Date() };
    const op = { $set: set };
    let until = null;
    if (days !== undefined) {
      const d = Number(days);
      if (!Number.isFinite(d) || d < 1 || d > 365) throw new HttpError(400, 'Days must be between 1 and 365');
      until = new Date(Date.now() + d * 24 * 60 * 60 * 1000);
      set.suspendedUntil = until;
    } else {
      op.$unset = { suspendedUntil: 1 };
    }

    await User.updateOne({ _id: target._id }, op);
    await revokeSessions(target._id, { reason: 'suspended' });
    logEvent(target._id, 'suspended', req, { by: req.user._id, reason, until });

    res.json({ success: true, message: 'Account suspended', suspendedUntil: until });
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/users/:id/ban  { reason }
router.post('/users/:id/ban', async (req, res, next) => {
  try {
    const target = await getTarget(req, { allowAdmin: false });
    const reason = requireReason((req.body || {}).reason);

    await User.updateOne(
      { _id: target._id },
      { $set: { status: 'banned', statusReason: reason, statusChangedAt: new Date() }, $unset: { suspendedUntil: 1 } }
    );
    await revokeSessions(target._id, { reason: 'banned' });
    logEvent(target._id, 'banned', req, { by: req.user._id, reason });

    res.json({ success: true, message: 'Account banned' });
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/users/:id/reinstate  { note? }  (sets the account back to active + clears the lock and the flag)
router.post('/users/:id/reinstate', async (req, res, next) => {
  try {
    const target = await getTarget(req);
    if (target.status === 'deleted') throw new HttpError(400, 'This account is deleted');

    const note = typeof (req.body || {}).note === 'string' ? req.body.note.trim().slice(0, 300) : undefined;

    await User.updateOne(
      { _id: target._id },
      {
        $set: { status: 'active', statusChangedAt: new Date(), flagged: false, failedLoginAttempts: 0 },
        $unset: { suspendedUntil: 1, statusReason: 1, flagReason: 1, lockUntil: 1 },
      }
    );
    logEvent(target._id, 'reinstated', req, { by: req.user._id, note });

    res.json({ success: true, message: 'Account reinstated' });
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/users/:id/flag  { flagged: true|false, reason? }  (mark / unmark as suspicious)
router.post('/users/:id/flag', async (req, res, next) => {
  try {
    const target = await getTarget(req, { allowAdmin: false });
    const { flagged } = req.body || {};
    if (typeof flagged !== 'boolean') throw new HttpError(400, 'flagged must be true or false');

    if (flagged) {
      const reason = requireReason((req.body || {}).reason);
      await User.updateOne({ _id: target._id }, { $set: { flagged: true, flagReason: reason } });
    } else {
      await User.updateOne({ _id: target._id }, { $set: { flagged: false }, $unset: { flagReason: 1 } });
    }
    logEvent(target._id, flagged ? 'flagged' : 'unflagged', req, { by: req.user._id });

    res.json({ success: true, message: flagged ? 'Account flagged as suspicious' : 'Suspicious flag removed' });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/identity/pending  (identity verification requests waiting for review)
router.get('/identity/pending', async (req, res, next) => {
  try {
    const users = await User.find({ 'identity.status': 'pending' }).sort({ 'identity.submittedAt': 1 }).limit(100);
    res.json({
      success: true,
      requests: users.map((u) => ({
        userId: u._id,
        name: u.name,
        phone: u.phone,
        role: u.role,
        submittedAt: u.identity.submittedAt,
      })),
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/identity/:id/:doc   (doc = front | back | selfie)  - identity documents are visible to admins only
router.get('/identity/:id/:doc', async (req, res, next) => {
  try {
    const doc = req.params.doc;
    if (!['front', 'back', 'selfie'].includes(doc)) throw new HttpError(400, 'Invalid document type');

    const target = await getTarget(req);
    const filename = target.identity && target.identity.docs && target.identity.docs[doc];
    if (!filename) throw new HttpError(404, 'Document not found');

    logEvent(target._id, 'identity_doc_viewed', req, { by: req.user._id, doc });

    res.set('Cache-Control', 'no-store');
    res.sendFile(path.join(PRIVATE_DIR, path.basename(filename)));
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/identity/:id  { decision: 'approve'|'reject', reason? }
router.post('/identity/:id', async (req, res, next) => {
  try {
    const target = await getTarget(req);
    const { decision } = req.body || {};

    if (!target.identity || target.identity.status !== 'pending') {
      throw new HttpError(400, 'This user has no identity request under review');
    }
    if (String(target._id) === String(req.user._id)) {
      throw new HttpError(403, 'You cannot review your own identity');
    }

    if (decision === 'approve') {
      await User.updateOne(
        { _id: target._id },
        {
          $set: { 'identity.status': 'approved', 'identity.reviewedAt': new Date(), 'identity.reviewedBy': req.user._id },
          $unset: { 'identity.rejectionReason': 1 },
        }
      );
      logEvent(target._id, 'identity_approved', req, { by: req.user._id });
      return res.json({ success: true, message: 'Identity verification approved' });
    }

    if (decision === 'reject') {
      const reason = requireReason((req.body || {}).reason);
      await User.updateOne(
        { _id: target._id },
        {
          $set: {
            'identity.status': 'rejected',
            'identity.reviewedAt': new Date(),
            'identity.reviewedBy': req.user._id,
            'identity.rejectionReason': reason,
          },
        }
      );
      logEvent(target._id, 'identity_rejected', req, { by: req.user._id, reason });
      return res.json({ success: true, message: 'Identity verification rejected' });
    }

    throw new HttpError(400, "decision must be 'approve' or 'reject'");
  } catch (err) {
    next(err);
  }
});

module.exports = router;