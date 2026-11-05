import {
  Schema,
  type ClientSession,
  type Connection,
  type Model,
} from "mongoose";
import { safeEqual } from "./crypto.js";
import type {
  ChallengeRecord,
  ChallengeStore,
  SessionRecord,
  SessionStore,
} from "./types.js";

interface Models<TClaims extends Record<string, unknown>> {
  Challenge: Model<any>;
  Session: Model<any>;
}
export function createAuthModels<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
>(connection: Connection, prefix = "SmsAuth"): Models<TClaims> {
  const challengeSchema = new Schema<ChallengeRecord>(
    {
      id: { type: String, required: true, unique: true },
      key: { type: String, required: true, index: true },
      phone: { type: String, required: true },
      phoneFingerprint: { type: String, required: true, index: true },
      purpose: { type: String, required: true },
      scope: { type: String, required: true },
      actorUserId: String,
      codeHash: { type: String, required: true, select: false },
      pepperVersion: { type: String, required: true },
      state: { type: String, required: true, index: true },
      attempts: { type: Number, required: true },
      maxAttempts: { type: Number, required: true },
      expiresAt: { type: Date, required: true, index: true },
      resendAvailableAt: { type: Date, required: true },
      createdAt: { type: Date, required: true },
    },
    { versionKey: false, collection: `${prefix.toLowerCase()}_challenges` },
  );
  challengeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  challengeSchema.index({
    scope: 1,
    purpose: 1,
    phoneFingerprint: 1,
    actorUserId: 1,
  });
  const sessionSchema = new Schema<SessionRecord<TClaims>>(
    {
      id: { type: String, required: true, unique: true },
      familyId: { type: String, required: true, index: true },
      userId: { type: String, required: true, index: true },
      refreshHash: { type: String, required: true, select: false },
      spentRefreshHashes: { type: [String], required: true, select: false },
      status: { type: String, required: true, index: true },
      roles: { type: [String], required: true },
      permissions: { type: [String], required: true },
      claims: { type: Schema.Types.Mixed, required: true },
      createdAt: { type: Date, required: true },
      expiresAt: { type: Date, required: true, index: true },
      lastUsedAt: { type: Date, required: true },
      userAgent: String,
      ipFingerprint: String,
    },
    {
      versionKey: "__v",
      optimisticConcurrency: true,
      collection: `${prefix.toLowerCase()}_sessions`,
    },
  );
  sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  const Challenge =
    (connection.models[`${prefix}Challenge`] as Model<any> | undefined) ??
    connection.model(`${prefix}Challenge`, challengeSchema);
  const Session =
    (connection.models[`${prefix}Session`] as Model<any> | undefined) ??
    connection.model(`${prefix}Session`, sessionSchema);
  return { Challenge, Session };
}
async function transaction<T>(
  connection: Connection,
  work: (session: ClientSession) => Promise<T>,
): Promise<T> {
  const session = await connection.startSession();
  let result!: T;
  try {
    await session.withTransaction(async () => {
      result = await work(session);
    });
    return result;
  } finally {
    await session.endSession();
  }
}
export class MongooseChallengeStore implements ChallengeStore {
  constructor(
    private readonly connection: Connection,
    private readonly model: Model<any>,
  ) {}
  async reserve(record: ChallengeRecord, now: Date) {
    return transaction(this.connection, async (session) => {
      const current = await this.model
        .findOne({ key: record.key, state: { $in: ["active", "dispatching"] } })
        .session(session);
      if (current && current.resendAvailableAt > now)
        return {
          status: "cooldown" as const,
          retryAfterMs: current.resendAvailableAt.getTime() - now.getTime(),
        };
      await this.model.updateMany(
        { key: record.key, state: { $in: ["active", "dispatching"] } },
        { $set: { state: "superseded" } },
        { session },
      );
      await this.model.create([record], { session });
      return { status: "reserved" as const };
    });
  }
  async activate(id: string) {
    return Boolean(
      await this.model.findOneAndUpdate(
        { id, state: "dispatching" },
        { $set: { state: "active" } },
      ),
    );
  }
  async fail(id: string) {
    await this.model.updateOne(
      { id, state: "dispatching" },
      { $set: { state: "failed" } },
    );
  }
  async consumeAttempt(key: string, candidateHash: string, now: Date) {
    return transaction(this.connection, async (session) => {
      const record = await this.model
        .findOne({ key, state: "active" })
        .select("+codeHash")
        .session(session);
      if (!record) return { status: "missing" as const };
      if (record.expiresAt <= now) {
        record.state = "expired";
        await record.save({ session });
        return { status: "expired" as const };
      }
      if (safeEqual(record.codeHash, candidateHash)) {
        record.state = "verified";
        await record.save({ session });
        return { status: "verified" as const, record: record.toObject() };
      }
      record.attempts += 1;
      if (record.attempts >= record.maxAttempts) {
        record.state = "locked";
        await record.save({ session });
        return { status: "locked" as const };
      }
      await record.save({ session });
      return { status: "invalid" as const };
    });
  }
}
export class MongooseSessionStore<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> implements SessionStore<TClaims> {
  constructor(
    private readonly connection: Connection,
    private readonly model: Model<any>,
  ) {}
  async create(record: SessionRecord<TClaims>) {
    await this.model.create(record);
  }
  async rotate(id: string, hash: string, next: string, now: Date) {
    return transaction(this.connection, async (session) => {
      const record = await this.model
        .findOne({ id })
        .select("+refreshHash +spentRefreshHashes")
        .session(session);
      if (!record || record.status !== "active" || record.expiresAt <= now)
        return { status: "invalid" as const };
      if (
        record.spentRefreshHashes.some((spent: string) =>
          safeEqual(spent, hash),
        )
      ) {
        await this.model.updateMany(
          { familyId: record.familyId },
          { $set: { status: "compromised" } },
          { session },
        );
        return { status: "reused" as const };
      }
      if (!safeEqual(record.refreshHash, hash))
        return { status: "invalid" as const };
      record.spentRefreshHashes.push(record.refreshHash);
      record.refreshHash = next;
      record.lastUsedAt = now;
      await record.save({ session });
      return {
        status: "rotated" as const,
        record: record.toObject() as SessionRecord<TClaims>,
      };
    });
  }
  async get(id: string) {
    return (
      ((await this.model
        .findOne({ id })
        .lean()) as SessionRecord<TClaims> | null) ?? undefined
    );
  }
  async list(userId: string) {
    return (await this.model
      .find({ userId })
      .lean()) as SessionRecord<TClaims>[];
  }
  async revokeOwned(id: string, userId: string) {
    return (
      (
        await this.model.updateOne(
          { id, userId },
          { $set: { status: "revoked" } },
        )
      ).matchedCount === 1
    );
  }
  async revokeFamily(familyId: string) {
    return (
      await this.model.updateMany(
        { familyId, status: "active" },
        { $set: { status: "revoked" } },
      )
    ).modifiedCount;
  }
  async revokeAll(userId: string) {
    return (
      await this.model.updateMany(
        { userId, status: "active" },
        { $set: { status: "revoked" } },
      )
    ).modifiedCount;
  }
}
