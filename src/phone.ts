import { AuthError } from "./errors.js";
const digitMap: Record<string, string> = {
  "۰": "0",
  "۱": "1",
  "۲": "2",
  "۳": "3",
  "۴": "4",
  "۵": "5",
  "۶": "6",
  "۷": "7",
  "۸": "8",
  "۹": "9",
  "٠": "0",
  "١": "1",
  "٢": "2",
  "٣": "3",
  "٤": "4",
  "٥": "5",
  "٦": "6",
  "٧": "7",
  "٨": "8",
  "٩": "9",
};
export function normalizeIranianPhone(value: string): `+98${string}` {
  let phone = value
    .trim()
    .replace(/[۰-۹٠-٩]/g, (digit) => digitMap[digit] ?? digit)
    .replace(/[\s()\-\.\u200c\u200d]/g, "");
  if (phone.startsWith("0098")) phone = `+98${phone.slice(4)}`;
  else if (phone.startsWith("98")) phone = `+${phone}`;
  else if (phone.startsWith("0")) phone = `+98${phone.slice(1)}`;
  if (!/^\+989\d{9}$/.test(phone))
    throw new AuthError("INVALID_INPUT", "Invalid phone number", 400);
  return phone as `+98${string}`;
}
