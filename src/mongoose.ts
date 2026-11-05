import {
  Schema,
  type ClientSession,
  type Connection,
  type Model,
} from "mongoose";
import { safeEqual } from "./crypto.js";
import type {
  AuditEvent,
  ChallengeRecord,
  ChallengeStore,
  Observer,
  SessionRecord,
  SessionStore,
} from "./types.js";

export interface AuthIdentityRecord {
  id: string;
  scope: string;
  phone: string;
  phoneFingerprint: string;
  userId: string;
  status: "active" | "disabled" | "deleted";
  verifiedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}
export interface AuthAuditRecord extends AuditEvent {
  expiresAt: Date;
}
export interface AuthModels {
  Challenge: Model<any>;
  Session: Model<any>;
  Identity: Model<AuthIdentityRecord>;
  Audit: Model<AuthAuditRecord>;
}
export function createAuthModels<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
>(connection: Connection, prefix = "SmsAuth"): AuthModels {
  const challengeSchema = new Schema<ChallengeRecord>(
    {
      id: { type: String, required: true, unique: true },
      key: { type: String, required: true },
      phone: { type: String, required: true },
      phoneFingerprint: { type: String, required: true, index: true },
      purpose: { type: String, required: true },
      scope: { type: String, required: true },
      actorUserId: String,
      actorSessionId: String,
      codeHash: { type: String, required: true, select: false },
      pepperVersion: { type: String, required: true },
      state: { type: String, required: true, index: true },
      attempts: { type: Number, required: true },
      maxAttempts: { type: Number, required: true },
      expiresAt: { type: Date, required: true },
      cleanupAt: { type: Date, required: true },
      resendAvailableAt: { type: Date, required: true },
      createdAt: { type: Date, required: true },
    },
    { versionKey: false, collection: `${prefix.toLowerCase()}_challenges` },
  );
  challengeSchema.index({ cleanupAt: 1 }, { expireAfterSeconds: 0 });
  challengeSchema.index(
    { key: 1 },
    {
      unique: true,
      partialFilterExpression: { state: { $in: ["dispatching", "active"] } },
    },
  );
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
      scope: { type: String, required: true, index: true },
      refreshHash: { type: String, required: true, select: false },
      spentRefreshHashes: { type: [String], required: true, select: false },
      status: { type: String, required: true, index: true },
      roles: { type: [String], required: true },
      permissions: { type: [String], required: true },
      claims: { type: Schema.Types.Mixed, required: true },
      createdAt: { type: Date, required: true },
      expiresAt: { type: Date, required: true },
      lastUsedAt: { type: Date, required: true },
      userAgent: String,
      ipFingerprint: String,
    },
    {
      versionKey: "__v",
      optimisticConcurrency: true,
      minimize: false,
      collection: `${prefix.toLowerCase()}_sessions`,
    },
  );
  sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  const identitySchema = new Schema<AuthIdentityRecord>(
    {
      id: { type: String, required: true, unique: true },
      scope: { type: String, required: true },
      phone: { type: String, required: true },
      phoneFingerprint: { type: String, required: true },
      userId: { type: String, required: true },
      status: { type: String, required: true },
      verifiedAt: Date,
      createdAt: { type: Date, required: true },
      updatedAt: { type: Date, required: true },
    },
    { versionKey: false, collection: `${prefix.toLowerCase()}_identities` },
  );
  identitySchema.index({ scope: 1, phoneFingerprint: 1 }, { unique: true });
  identitySchema.index({ scope: 1, userId: 1 }, { unique: true });
  const auditSchema = new Schema<AuthAuditRecord>(
    {
      type: { type: String, required: true },
      occurredAt: { type: Date, required: true },
      correlationId: String,
      userId: String,
      sessionId: String,
      phoneFingerprint: String,
      purpose: String,
      metadata: Schema.Types.Mixed,
      expiresAt: { type: Date, required: true },
    },
    { versionKey: false, collection: `${prefix.toLowerCase()}_audit` },
  );
  auditSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  auditSchema.index({ occurredAt: 1, type: 1 });
  const Challenge =
    (connection.models[`${prefix}Challenge`] as Model<any> | undefined) ??
    connection.model(`${prefix}Challenge`, challengeSchema);
  const Session =
    (connection.models[`${prefix}Session`] as Model<any> | undefined) ??
    connection.model(`${prefix}Session`, sessionSchema);
  const Identity =
    (connection.models[`${prefix}Identity`] as
      Model<AuthIdentityRecord> | undefined) ??
    connection.model<AuthIdentityRecord>(`${prefix}Identity`, identitySchema);
  const Audit =
    (connection.models[`${prefix}Audit`] as
      Model<AuthAuditRecord> | undefined) ??
    connection.model<AuthAuditRecord>(`${prefix}Audit`, auditSchema);
  return { Challenge, Session, Identity, Audit };
}

export class MongooseAuditObserver implements Observer {
  constructor(
    private readonly model: Model<AuthAuditRecord>,
    private readonly retentionMs = 90 * 24 * 60 * 60 * 1000,
  ) {}
  async emit(event: AuditEvent) {
    await this.model.create({
      ...event,
      expiresAt: new Date(event.occurredAt.getTime() + this.retentionMs),
    });
  }
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
    try {
      return await transaction(this.connection, async (session) => {
        const current = await this.model
          .findOne({
            key: record.key,
            state: { $in: ["active", "dispatching"] },
          })
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
    } catch (error) {
      if (
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === 11000
      ) {
        const current = await this.model.findOne({
          key: record.key,
          state: { $in: ["active", "dispatching"] },
        });
        return {
          status: "cooldown" as const,
          retryAfterMs: Math.max(
            1,
            (current?.resendAvailableAt?.getTime() ?? now.getTime() + 1000) -
              now.getTime(),
          ),
        };
      }
      throw error;
    }
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
          { id, userId, status: "active" },
          { $set: { status: "revoked" } },
        )
      ).modifiedCount === 1
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
