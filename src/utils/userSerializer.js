const env = require('../config/env');

function photoUrl(user) {
  return user.photo ? `${env.BASE_URL}/uploads/avatars/${user.photo}` : null;
}

// the data returned to a user about themselves (nothing sensitive)
function publicUser(u) {
  const n = (u.settings && u.settings.notifications) || {};
  return {
    id: u._id,
    name: u.name,
    phone: u.phone,
    email: u.email || null,
    photoUrl: photoUrl(u),
    role: u.role,
    gender: u.gender || null,
    dateOfBirth: u.dateOfBirth || null,
    isPhoneVerified: u.isPhoneVerified,
    isEmailVerified: !!u.email,
    settings: {
      language: (u.settings && u.settings.language) || 'ar',
      notifications: {
        push: n.push !== false,
        sms: n.sms !== false,
        email: n.email !== false,
        promotions: n.promotions === true,
      },
    },
    identityStatus: (u.identity && u.identity.status) || 'none',
    createdAt: u.createdAt,
  };
}

// the data an admin sees about a user
function adminUserView(u) {
  return {
    id: u._id,
    name: u.name,
    phone: u.phone,
    email: u.email || null,
    role: u.role,
    status: u.status,
    statusReason: u.statusReason || null,
    suspendedUntil: u.suspendedUntil || null,
    flagged: u.flagged,
    flagReason: u.flagReason || null,
    lockUntil: u.lockUntil || null,
    identityStatus: (u.identity && u.identity.status) || 'none',
    isPhoneVerified: u.isPhoneVerified,
    createdAt: u.createdAt,
    lastLoginAt: u.lastLoginAt || null,
  };
}

module.exports = { photoUrl, publicUser, adminUserView };