'use strict';

// ── Input validation helpers ───────────────────────────────────────────────
// Call these at the TOP of every route handler before touching the DB.
// Returns an error string on failure, null on success.

const cfg = require('../config');

// ── Primitives ────────────────────────────────────────────────────────────
function isString(v)  { return typeof v === 'string'; }
function isInt(v)     { return Number.isInteger(Number(v)) && !isNaN(Number(v)); }

function requireString(val, name, { min = 1, max = 1024 } = {}) {
  if (!isString(val) || val.trim().length < min)
    return `${name} is required and must be a non-empty string`;
  if (val.trim().length > max)
    return `${name} must be at most ${max} characters`;
  return null;
}

function requireInt(val, name, { min = 0 } = {}) {
  const n = parseInt(val, 10);
  if (isNaN(n)) return `${name} must be a valid integer`;
  if (n < min)  return `${name} must be at least ${min}`;
  return null;
}

function requireEnum(val, name, allowed) {
  if (!allowed.includes(val))
    return `${name} must be one of: ${allowed.join(', ')}`;
  return null;
}

// ── Auth validation ───────────────────────────────────────────────────────
function validateCredentials({ username, password }) {
  return (
    requireString(username, 'username', { max: cfg.MAX_USERNAME_LEN }) ||
    requireString(password, 'password', { min: 1, max: cfg.MAX_PASSWORD_LEN })
  );
}

function validateNewPassword(password) {
  if (!isString(password) || password.length < cfg.MIN_PASSWORD_LEN)
    return `Password must be at least ${cfg.MIN_PASSWORD_LEN} characters`;
  if (password.length > cfg.MAX_PASSWORD_LEN)
    return `Password must be at most ${cfg.MAX_PASSWORD_LEN} characters`;
  // Complexity: at least one uppercase letter, one lowercase, and one digit or special char
  if (!/[A-Z]/.test(password))
    return 'Password must contain at least one uppercase letter (A-Z)';
  if (!/[a-z]/.test(password))
    return 'Password must contain at least one lowercase letter (a-z)';
  if (!/[0-9!@#$%^&*()_+\-=\[\]{};':"\|,.<>\/?]/.test(password))
    return 'Password must contain at least one digit or special character';
  return null;
}

// ── Sanitize a plain string for DB storage ────────────────────────────────
// Trims whitespace and removes null bytes.
function sanitize(val) {
  if (!isString(val)) return '';
  return val.trim().replace(/\0/g, '');
}

module.exports = {
  requireString,
  requireInt,
  requireEnum,
  validateCredentials,
  validateNewPassword,
  sanitize,
  isString,
  isInt,
};
