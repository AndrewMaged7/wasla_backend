const express = require('express');
const env = require('../config/env');
const authRoutes = require('./auth.routes');
const profileRoutes = require('./profile.routes');
const accountRoutes = require('./account.routes');
const adminRoutes = require('./admin.routes');

const router = express.Router();

// GET /api/legal  (terms and privacy policy versions and links for the frontend)
router.get('/legal', (req, res) => {
  res.json({
    success: true,
    terms: { version: env.TERMS_VERSION, url: env.TERMS_URL },
    privacy: { version: env.PRIVACY_VERSION, url: env.PRIVACY_URL },
  });
});

router.use('/auth', authRoutes);
router.use('/profile', profileRoutes);
router.use('/account', accountRoutes);
router.use('/admin', adminRoutes);

module.exports = router;