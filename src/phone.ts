import { AuthError } from './errors.js';
const persian = '۰۱۲۳۴۵۶۷۸۹';
export function normalizeIranianPhone(value: string): `+98${string}` {
  let phone = value.trim().replace(/[۰-۹]/g, c => String(persian.indexOf(c))).replace(/[\s()-]/g, '');
  if (phone.startsWith('0098')) phone = `+98${phone.slice(4)}`;
  else if (phone.startsWith('98')) phone = `+${phone}`;
  else if (phone.startsWith('0')) phone = `+98${phone.slice(1)}`;
  if (!/^\+989\d{9}$/.test(phone)) throw new AuthError('INVALID_INPUT', 'Invalid Iranian mobile number', 400);
  return phone as `+98${string}`;
}
