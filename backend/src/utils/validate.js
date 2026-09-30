/**
 * Validation helpers — called before saving to DB.
 * Returns { valid: true } or { valid: false, message: '...' }
 */

const EMAIL_RE    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_RE    = /^[\d\s\+\-\(\)]{7,15}$/;
const PASSWORD_MIN = 8;

function validateEmail(email) {
  if (!email || typeof email !== 'string') return 'Email is required';
  if (!EMAIL_RE.test(email.trim()))         return 'Invalid email address';
  return null;
}

function validatePassword(password) {
  if (!password || typeof password !== 'string') return 'Password is required';
  if (password.length < PASSWORD_MIN)
    return `Password must be at least ${PASSWORD_MIN} characters`;
  return null;
}

function validatePhone(phone) {
  if (!phone) return null;  // optional
  if (!PHONE_RE.test(phone)) return 'Invalid phone number';
  return null;
}

function validateCompanyName(name) {
  if (!name || typeof name !== 'string' || name.trim().length < 2)
    return 'Company name must be at least 2 characters';
  if (name.trim().length > 100) return 'Company name too long (max 100 characters)';
  return null;
}

function validateSystemName(name) {
  if (!name || typeof name !== 'string' || name.trim().length < 1)
    return 'System name is required';
  if (name.trim().length > 80) return 'System name too long (max 80 characters)';
  return null;
}

function validateDeptName(name) {
  if (!name || typeof name !== 'string' || name.trim().length < 1)
    return 'Department name is required';
  if (name.trim().length > 80) return 'Department name too long (max 80 characters)';
  return null;
}

/**
 * Run multiple validators and return first error found.
 * validators: array of [errorMsg | null]
 */
function firstError(validators) {
  for (const err of validators) {
    if (err) return { valid: false, message: err };
  }
  return { valid: true };
}

module.exports = {
  validateEmail,
  validatePassword,
  validatePhone,
  validateCompanyName,
  validateSystemName,
  validateDeptName,
  firstError,
};
