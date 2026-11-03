const HttpError = require('./HttpError');
const { PASSWORD_REGEX } = require('./regex');

function validatePassword(password, confirmPassword) {
  const errors = [];
  if (typeof password !== 'string' || !PASSWORD_REGEX.test(password)) {
    errors.push('Password must be 8-64 characters and include an uppercase letter, a lowercase letter and a number');
  }
  if (confirmPassword !== undefined && password !== confirmPassword) {
    errors.push('Password and confirmation do not match');
  }
  return errors;
}

function validateSignup({ name, phone, password, confirmPassword, acceptTerms, acceptPrivacy, role }) {
  const errors = [];

  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 50) {
    errors.push('Name must be between 2 and 50 characters');
  }
  if (!phone) errors.push('Invalid phone number');
  errors.push(...validatePassword(password, confirmPassword));
  if (role !== undefined && !['rider', 'driver'].includes(role)) {
    errors.push('Account type must be rider or driver');
  }
  if (acceptTerms !== true) errors.push('You must accept the Terms and Conditions');
  if (acceptPrivacy !== true) errors.push('You must accept the Privacy Policy');

  return errors;
}

// admin actions (suspend / ban / flag / reject identity) must always come with a reason
function requireReason(reason) {
  if (typeof reason !== 'string' || reason.trim().length < 3 || reason.trim().length > 300) {
    throw new HttpError(400, 'A reason is required (3 to 300 characters)');
  }
  return reason.trim();
}

module.exports = { validatePassword, validateSignup, requireReason };