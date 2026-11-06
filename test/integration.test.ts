import mongoose from "mongoose";
import { createClient } from "redis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { keyedHash } from "../src/crypto.js";
import {
  createAuthModels,
  MongooseChallengeStore,
  MongooseSessionStore,
} from "../src/mongoose.js";
import { RedisRateLimiter } from "../src/redis.js";
import type { ChallengeRecord, SessionRecord } from "../src/types.js";

const integration = process.env.INTEGRATION === "1" ? describe : describe.skip;
integration("real persistence concurrency", () => {
  const connection = mongoose.createConnection();
  const redis = createClient({
    url: process.env.REDIS_URL ?? "redis://127.0.0.1:6380",
  });
  beforeAll(async () => {
    await connection.openUri(
      process.env.MONGO_URL ??
        "mongodb://127.0.0.1:27018/sms_auth_test?replicaSet=rs0&directConnection=true",
    );
    await connection.dropDatabase();
    await redis.connect();
  }, 30_000);
  afterAll(async () => {
    await redis.quit();
    await connection.close();
  });
  it("allows only one active challenge reservation and one verification", async () => {
    const models = createAuthModels(connection, "Integration");
    await models.Challenge.syncIndexes();
    const store = new MongooseChallengeStore(connection, models.Challenge);
    const now = new Date();
    const secret = new Uint8Array(32).fill(4);
    const hash = keyedHash(secret, "otp", "code");
    const base: Omit<ChallengeRecord, "id"> = {
      key: "challenge",
      phone: "+989123456789",
      phoneFingerprint: "fingerprint",
      purpose: "login",
      scope: "tenant",
      codeHash: hash,
      pepperVersion: "p1",
      state: "dispatching",
      attempts: 0,
      maxAttempts: 5,
      createdAt: now,
      expiresAt: new Date(now.getTime() + 60_000),
      cleanupAt: new Date(now.getTime() + 120_000),
      resendAvailableAt: new Date(now.getTime() + 30_000),
    };
    const reservations = await Promise.all(
      Array.from({ length: 10 }, (_, index) =>
        store.reserve({ ...base, id: `c${index}` }, now),
      ),
    );
    expect(
      reservations.filter((result) => result.status === "reserved"),
    ).toHaveLength(1);
    const winner = reservations.findIndex(
      (result) => result.status === "reserved",
    );
    await store.activate(`c${winner}`);
    const attempts = await Promise.all(
      Array.from({ length: 10 }, () =>
        store.consumeAttempt("challenge", hash, now),
      ),
    );
    expect(
      attempts.filter((result) => result.status === "verified"),
    ).toHaveLength(1);

    await store.reserve(
      { ...base, id: "versioned", key: "challenge-old", codeHash: hash },
      now,
    );
    await store.activate("versioned");
    const versionedAttempts = await Promise.all(
      Array.from({ length: 10 }, () =>
        store.consumeAttemptVersioned(
          [
            {
              pepperVersion: "p2",
              key: "challenge-new",
              candidateHash: "wrong",
            },
            {
              pepperVersion: "p1",
              key: "challenge-old",
              candidateHash: hash,
            },
          ],
          now,
        ),
      ),
    );
    expect(
      versionedAttempts.filter((result) => result.status === "verified"),
    ).toHaveLength(1);
  }, 30_000);
  it("rotates a refresh token atomically", async () => {
    const models = createAuthModels(connection, "Integration");
    await models.Session.syncIndexes();
    const store = new MongooseSessionStore(connection, models.Session);
    const now = new Date();
    const record: SessionRecord = {
      id: "session",
      familyId: "family",
      userId: "user",
      scope: "tenant",
      refreshHash: "current",
      spentRefreshHashes: [],
      status: "active",
      roles: [],
      permissions: [],
      claims: {},
      createdAt: now,
      lastUsedAt: now,
      expiresAt: new Date(now.getTime() + 60_000),
    };
    await store.create(record);
    const rotations = await Promise.all(
      Array.from({ length: 10 }, (_, index) =>
        store.rotate("session", "current", `next-${index}`, now, {
          nextPepperVersion: "p2",
          authorization: {
            roles: ["admin"],
            permissions: ["orders.read"],
            claims: { plan: "pro" },
          },
        }),
      ),
    );
    expect(
      rotations.filter((result) => result.status === "rotated"),
    ).toHaveLength(1);
    expect(await store.get("session")).toMatchObject({
      refreshPepperVersion: "p2",
      roles: ["admin"],
      permissions: ["orders.read"],
      claims: { plan: "pro" },
    });
  }, 30_000);
  it("enforces a distributed Redis bucket", async () => {
    await redis.flushDb();
    const limiter = new RedisRateLimiter(redis, {
      prefix: "integration",
      limit: 3,
      windowMs: 60_000,
    });
    const results = await Promise.all(
      Array.from({ length: 10 }, () =>
        limiter.consume({
          operation: "request_code",
          keys: ["phone:a", "ip:b"],
          now: new Date(),
        }),
      ),
    );
    expect(results.filter((result) => result.allowed)).toHaveLength(3);
  });
});
