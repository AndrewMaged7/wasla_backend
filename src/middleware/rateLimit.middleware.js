const rateLimit = require('express-rate-limit');
const env = require('../config/env');

function makeLimiter(windowMs, max, message) {
  if (env.RATE_LIMIT_DISABLED) return (req, res, next) => next();
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message },
  });
}

module.exports = {
  signupLimiter: makeLimiter(15 * 60 * 1000, 10, 'Too many attempts, please try again later'),
  loginLimiter: makeLimiter(15 * 60 * 1000, 20, 'Too many login attempts, please try again in 15 minutes'),
  otpVerifyLimiter: makeLimiter(15 * 60 * 1000, 20, 'Too many attempts, please try again later'),
  otpSendLimiter: makeLimiter(60 * 60 * 1000, 10, 'Too many requests, please try again in an hour'),
  sensitiveLimiter: makeLimiter(15 * 60 * 1000, 20, 'Too many attempts, please try again later'),
  uploadLimiter: makeLimiter(60 * 60 * 1000, 20, 'Too many uploads, please try again in an hour'),
  identityLimiter: makeLimiter(60 * 60 * 1000, 5, 'Too many attempts, please try again in an hour'),
};