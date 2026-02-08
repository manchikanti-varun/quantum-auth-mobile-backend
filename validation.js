/** Email, password, display name, security code validation. */

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_MAX_LENGTH = 128;
const DISPLAY_NAME_MAX_LENGTH = 50;

function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const trimmed = email.trim();
  return trimmed.length > 0 && trimmed.length <= 254 && EMAIL_REGEX.test(trimmed);
}

function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, message: 'Password is required' };
  }
  const p = password;
  if (p.length < PASSWORD_MIN_LENGTH) {
    return { valid: false, message: `Password must be at least ${PASSWORD_MIN_LENGTH} characters` };
  }
  if (p.length > PASSWORD_MAX_LENGTH) {
    return { valid: false, message: `Password must be at most ${PASSWORD_MAX_LENGTH} characters` };
  }
  if (!/[a-z]/.test(p)) {
    return { valid: false, message: 'Password must contain at least one lowercase letter' };
  }
  if (!/[A-Z]/.test(p)) {
    return { valid: false, message: 'Password must contain at least one uppercase letter' };
  }
  if (!/[0-9]/.test(p)) {
    return { valid: false, message: 'Password must contain at least one number' };
  }
  if (!/[^a-zA-Z0-9]/.test(p)) {
    return { valid: false, message: 'Password must contain at least one special character (!@#$%^&* etc.)' };
  }
  return { valid: true };
}

function validateRegister({ email, password, displayName }) {
  const errors = [];
  if (!email || !email.trim()) {
    errors.push('Email is required');
  } else if (!isValidEmail(email)) {
    errors.push('Enter a valid email address');
  }
  const pwResult = validatePassword(password);
  if (!pwResult.valid) {
    errors.push(pwResult.message);
  }
  if (displayName !== undefined && displayName !== null && displayName !== '') {
    const dn = String(displayName).trim();
    if (dn.length > DISPLAY_NAME_MAX_LENGTH) {
      errors.push(`Display name must be at most ${DISPLAY_NAME_MAX_LENGTH} characters`);
    }
  }
  return errors;
}

function validateSecurityCode(code) {
  if (!code || typeof code !== 'string') {
    return { valid: false, message: 'Security code is required' };
  }
  const c = String(code).replace(/\s/g, '');
  if (!/^\d{4,6}$/.test(c)) {
    return { valid: false, message: 'Security code must be 4–6 digits' };
  }
  return { valid: true, value: c };
}

function validateLogin({ email, password }) {
  const errors = [];
  if (!email || !email.trim()) {
    errors.push('Email is required');
  } else if (!isValidEmail(email)) {
    errors.push('Enter a valid email address');
  }
  if (!password || typeof password !== 'string') {
    errors.push('Password is required');
  } else if (password.trim().length === 0) {
    errors.push('Password is required');
  }
  return errors;
}

module.exports = {
  isValidEmail,
  validatePassword,
  validateSecurityCode,
  validateRegister,
  validateLogin,
  EMAIL_REGEX,
  PASSWORD_MIN_LENGTH,
};
