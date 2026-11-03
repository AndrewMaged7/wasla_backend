const crypto = require('crypto');
const env = require('../config/env');
const {
  OTP_LENGTH,
  OTP_EXPIRES_MS,
  OTP_MAX_ATTEMPTS,
  OTP_RESEND_COOLDOWN_MS,
} = require('../config/constants');
const { Otp } = require('../models');
const { sendSms, sendEmail } = require('./messaging.service');

function generateOtp() {
  return String(crypto.randomInt(0, 10 ** OTP_LENGTH)).padStart(OTP_LENGTH, '0');
}

// only the hash (HMAC) is stored, never the code itself
function hashOtp(target, purpose, code) {
  return crypto.createHmac('sha256', env.JWT_SECRET).update(`${target}:${purpose}:${code}`).digest('hex');
}

function safeEqualHex(a, b) {
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

// sends a new code (SMS if target is a phone number, email if it is an email address).
// returns { sent: false, retryAfter } while the resend cooldown is still running
async function sendOtp(target, purpose) {
  const existing = await Otp.findOne({ target, purpose });
  if (existing) {
    const wait = OTP_RESEND_COOLDOWN_MS - (Date.now() - existing.lastSentAt.getTime());
    if (wait > 0) return { sent: false, retryAfter: Math.ceil(wait / 1000) };
  }

  const code = generateOtp();

  await Otp.findOneAndUpdate(
    { target, purpose },
    {
      codeHash: hashOtp(target, purpose, code),
      expiresAt: new Date(Date.now() + OTP_EXPIRES_MS),
      attempts: 0,
      lastSentAt: new Date(),
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );

  const text = `Your verification code is ${code}. It is valid for ${OTP_EXPIRES_MS / 60000} minutes. Do not share it with anyone.`;

  try {
    if (target.includes('@')) await sendEmail(target, 'Your verification code', text);
    else await sendSms(target, text);
  } catch (err) {
    await Otp.deleteOne({ target, purpose });
    throw err;
  }

  return { sent: true };
}

// verifies a code. every attempt is counted, and the code is deleted after a successful check
async function verifyOtp(target, purpose, code) {
  if (typeof code !== 'string' || !new RegExp(`^\\d{${OTP_LENGTH}}$`).test(code)) return false;

  const record = await Otp.findOneAndUpdate(
    { target, purpose, expiresAt: { $gt: new Date() }, attempts: { $lt: OTP_MAX_ATTEMPTS } },
    { $inc: { attempts: 1 } },
    { new: true }
  );
  if (!record) return false;

  const ok = safeEqualHex(record.codeHash, hashOtp(target, purpose, code));
  if (ok) await Otp.deleteOne({ _id: record._id });
  return ok;
}

module.exports = { sendOtp, verifyOtp };