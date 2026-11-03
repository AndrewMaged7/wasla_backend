const { EMAIL_REGEX } = require('./regex');

// converts a phone number to a unified international format: 01012345678 -> +201012345678
function normalizePhone(raw) {
  if (typeof raw !== 'string') return null;
  let p = raw.trim().replace(/[\s\-()]/g, '');

  if (/^01[0125]\d{8}$/.test(p)) p = '+20' + p.slice(1); // local Egyptian number
  else if (/^201[0125]\d{8}$/.test(p)) p = '+' + p; // 20 without the +
  else if (p.startsWith('00')) p = '+' + p.slice(2); // 00 instead of +

  return /^\+[1-9]\d{7,14}$/.test(p) ? p : null;
}

function normalizeEmail(raw) {
  if (typeof raw !== 'string') return null;
  const e = raw.trim().toLowerCase();
  return e.length <= 254 && EMAIL_REGEX.test(e) ? e : null;
}

module.exports = { normalizePhone, normalizeEmail };