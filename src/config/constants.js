const path = require('path');

// project root (the folder that contains src/, uploads/, private/ and .env)
const ROOT_DIR = path.join(__dirname, '..', '..');

const UPLOAD_DIR = path.join(ROOT_DIR, 'uploads'); // public (profile photos only)
const AVATAR_DIR = path.join(UPLOAD_DIR, 'avatars');
const PRIVATE_DIR = path.join(ROOT_DIR, 'private', 'identity'); // private (identity documents, never served publicly)

module.exports = {
  ROOT_DIR,
  UPLOAD_DIR,
  AVATAR_DIR,
  PRIVATE_DIR,

  OTP_LENGTH: 6,
  OTP_EXPIRES_MS: 5 * 60 * 1000, // 5 minutes
  OTP_MAX_ATTEMPTS: 5, // max wrong attempts per code
  OTP_RESEND_COOLDOWN_MS: 60 * 1000, // 1 minute between sends

  MAX_FAILED_LOGINS: 5, // after this the account is temporarily locked
  LOCK_MS: 15 * 60 * 1000, // temporary lock duration

  AVATAR_MAX_BYTES: 2 * 1024 * 1024, // 2MB
  ID_DOC_MAX_BYTES: 5 * 1024 * 1024, // 5MB
};