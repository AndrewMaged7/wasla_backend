const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,64}$/;
const OBJECT_ID_REGEX = /^[a-f\d]{24}$/i;

// escapes special characters so user input can be used safely inside a RegExp
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = { EMAIL_REGEX, PASSWORD_REGEX, OBJECT_ID_REGEX, escapeRegex };