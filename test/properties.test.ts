import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { normalizeIranianPhone } from "../src/phone.js";
import { parseCookie } from "../src/transport.js";

describe("property and fuzz boundaries", () => {
  it("never throws while parsing arbitrary cookie headers", () => {
    fc.assert(
      fc.property(fc.string(), fc.string({ minLength: 1 }), (header, name) => {
        expect(() => parseCookie(header, name)).not.toThrow();
      }),
      { numRuns: 1000 },
    );
  });
  it("normalizes all canonical Iranian mobile suffixes", () => {
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 0, max: 9 }), {
          minLength: 8,
          maxLength: 8,
        }),
        (digits) => {
          const suffix = digits.join("");
          const canonical = `+9891${suffix}`;
          expect(normalizeIranianPhone(`091${suffix}`)).toBe(canonical);
        },
      ),
      { numRuns: 500 },
    );
  });
  it("rejects arbitrary non-phone strings", () => {
    fc.assert(
      fc.property(
        fc.string().filter((value) => !/^\+989\d{9}$/.test(value)),
        (value) => {
          try {
            const normalized = normalizeIranianPhone(value);
            expect(normalized).toMatch(/^\+989\d{9}$/);
          } catch (error) {
            expect(error).toBeInstanceOf(Error);
          }
        },
      ),
      { numRuns: 1000 },
    );
  });
});
