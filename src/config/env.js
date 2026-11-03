const path = require('path');

// loads the .env file from the project root (works no matter where you start the server from)
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

const env = {
  PORT,
  NODE_ENV,
  IS_PRODUCTION: NODE_ENV === 'production',
  MONGO_URI: process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/auth_demo',
  JWT_SECRET: process.env.JWT_SECRET,
  BASE_URL: process.env.BASE_URL || `http://localhost:${PORT}`,
  TRUST_PROXY: process.env.TRUST_PROXY === 'true',

  SESSION_DAYS: Number(process.env.SESSION_DAYS) || 7,
  MAX_SESSIONS: Number(process.env.MAX_SESSIONS) || 5, // max devices signed in at the same time

  TERMS_VERSION: process.env.TERMS_VERSION || '1.0',
  PRIVACY_VERSION: process.env.PRIVACY_VERSION || '1.0',
  TERMS_URL: process.env.TERMS_URL || null,
  PRIVACY_URL: process.env.PRIVACY_URL || null,

  // Rate limiting can only be disabled outside production (used by the automated tests)
  RATE_LIMIT_DISABLED: process.env.DISABLE_RATE_LIMIT === 'true' && NODE_ENV !== 'production',

  ADMIN_PHONES_RAW: process.env.ADMIN_PHONES || '',

  TWILIO_ACCOUNT_SID: process.env.TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN: process.env.TWILIO_AUTH_TOKEN,
  TWILIO_FROM: process.env.TWILIO_FROM,

  SMTP_HOST: process.env.SMTP_HOST,
  SMTP_PORT: Number(process.env.SMTP_PORT) || 587,
  SMTP_USER: process.env.SMTP_USER,
  SMTP_PASS: process.env.SMTP_PASS,
  MAIL_FROM: process.env.MAIL_FROM,
};

if (!env.JWT_SECRET) {
  console.error('ERROR: JWT_SECRET is missing. Add it to your .env file.');
  process.exit(1);
}

module.exports = env;