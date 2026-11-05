import mongoose from "mongoose";
import { describe, expect, it } from "vitest";
import { createAuthModels } from "../src/mongoose.js";
describe("Mongoose schema contracts", () => {
  it("defines grace TTL and one-active-challenge uniqueness", () => {
    const connection = mongoose.createConnection();
    const { Challenge, Session } = createAuthModels(connection, "Contract");
    const challengeIndexes = Challenge.schema.indexes();
    expect(challengeIndexes).toContainEqual([
      { cleanupAt: 1 },
      { expireAfterSeconds: 0 },
    ]);
    const activeIndex = challengeIndexes.find(
      ([keys, options]) => keys.key === 1 && options.unique,
    );
    expect(activeIndex?.[1].partialFilterExpression).toEqual({
      state: { $in: ["dispatching", "active"] },
    });
    const expiresIndexes = challengeIndexes.filter(
      ([keys]) => keys.expiresAt === 1,
    );
    expect(expiresIndexes).toHaveLength(0);
    expect(
      Session.schema
        .indexes()
        .some(
          ([keys, options]) =>
            keys.expiresAt === 1 && options.expireAfterSeconds === 0,
        ),
    ).toBe(true);
  });
});
