const env = require('./env');
const { normalizePhone } = require('../utils/normalization');
const { User } = require('../models');

// phone numbers from ADMIN_PHONES in the .env file, in international format
const ADMIN_PHONES = env.ADMIN_PHONES_RAW.split(',')
  .map((s) => normalizePhone(s))
  .filter(Boolean);

function isAdminPhone(phone) {
  return ADMIN_PHONES.includes(phone);
}

// makes every already-verified admin phone an admin (runs once when the server starts)
async function promoteAdminPhones() {
  if (!ADMIN_PHONES.length) return;
  await User.updateMany({ phone: { $in: ADMIN_PHONES }, isPhoneVerified: true }, { $set: { role: 'admin' } });
}

module.exports = { ADMIN_PHONES, isAdminPhone, promoteAdminPhones };