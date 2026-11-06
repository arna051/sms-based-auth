import { safeEqual } from "./crypto.js";
import type {
  ChallengeRecord,
  ChallengeStore,
  RateLimiter,
  RateLimitRequest,
  SessionRecord,
  SessionStore,
} from "./types.js";

export class MemoryChallengeStore implements ChallengeStore {
  private readonly recordsByKey = new Map<string, ChallengeRecord>();
  private readonly keysById = new Map<string, string>();

  async reserve(record: ChallengeRecord, now: Date) {
    const current = this.recordsByKey.get(record.key);
    if (
      current &&
      (["active", "dispatching", "verifying"] as const).includes(
        current.state as "active" | "dispatching" | "verifying",
      ) &&
      current.resendAvailableAt > now
    ) {
      return {
        status: "cooldown" as const,
        retryAfterMs: current.resendAvailableAt.getTime() - now.getTime(),
      };
    }
    if (
      current &&
      (["active", "dispatching", "verifying"] as const).includes(
        current.state as "active" | "dispatching" | "verifying",
      )
    )
      current.state = "superseded";
    this.recordsByKey.set(record.key, structuredClone(record));
    this.keysById.set(record.id, record.key);
    return { status: "reserved" as const };
  }

  async activate(id: string) {
    const key = this.keysById.get(id);
    const record = key ? this.recordsByKey.get(key) : undefined;
    if (!record || record.id !== id || record.state !== "dispatching")
      return false;
    record.state = "active";
    return true;
  }

  async fail(id: string) {
    const key = this.keysById.get(id);
    const record = key ? this.recordsByKey.get(key) : undefined;
    if (record?.id === id && record.state === "dispatching")
      record.state = "failed";
  }

  async consumeAttempt(key: string, hash: string, now: Date) {
    const record = this.recordsByKey.get(key);
    if (!record || record.state !== "active")
      return { status: "missing" as const };
    if (record.expiresAt <= now) {
      record.state = "expired";
      return { status: "expired" as const };
    }
    if (safeEqual(record.codeHash, hash)) {
      record.state = "verifying";
      return { status: "verified" as const, record: structuredClone(record) };
    }
    record.attempts += 1;
    if (record.attempts >= record.maxAttempts) {
      record.state = "locked";
      return { status: "locked" as const };
    }
    return { status: "invalid" as const };
  }

  async consumeAttemptVersioned(
    candidates: ReadonlyArray<{
      pepperVersion: string;
      key: string;
      candidateHash: string;
    }>,
    now: Date,
  ) {
    const record = candidates
      .map((item) => this.recordsByKey.get(item.key))
      .find((item) => item?.state === "active");
    if (!record) return { status: "missing" as const };
    const candidate = candidates.find(
      (item) =>
        item.key === record.key && item.pepperVersion === record.pepperVersion,
    );
    if (!candidate) return { status: "missing" as const };
    return this.consumeAttempt(candidate.key, candidate.candidateHash, now);
  }

  async completeVerification(id: string) {
    const key = this.keysById.get(id);
    const record = key ? this.recordsByKey.get(key) : undefined;
    if (!record || record.id !== id || record.state !== "verifying")
      return false;
    record.state = "verified";
    return true;
  }

  async releaseVerification(id: string) {
    const key = this.keysById.get(id);
    const record = key ? this.recordsByKey.get(key) : undefined;
    if (record?.id === id && record.state === "verifying")
      record.state = "active";
  }
}

export class MemorySessionStore<
  TClaims extends Record<string, unknown> = Record<string, unknown>,
> implements SessionStore<TClaims> {
  private readonly records = new Map<string, SessionRecord<TClaims>>();
  async create(record: SessionRecord<TClaims>) {
    this.records.set(record.id, structuredClone(record));
  }
  async rotate(
    id: string,
    hash: string,
    next: string,
    now: Date,
    update?: {
      nextPepperVersion?: string;
      presentedHashes?: string[];
      authorization?: {
        roles: string[];
        permissions: string[];
        claims: TClaims;
      };
    },
  ) {
    const record = this.records.get(id);
    if (!record || record.status !== "active" || record.expiresAt <= now)
      return { status: "invalid" as const };
    const presentedHashes = [hash, ...(update?.presentedHashes ?? [])];
    if (
      record.spentRefreshHashes.some((spent) =>
        presentedHashes.some((presented) => safeEqual(spent, presented)),
      )
    ) {
      for (const candidate of this.records.values())
        if (candidate.familyId === record.familyId)
          candidate.status = "compromised";
      return { status: "reused" as const };
    }
    if (!safeEqual(record.refreshHash, hash))
      return { status: "invalid" as const };
    record.spentRefreshHashes.push(record.refreshHash);
    record.refreshHash = next;
    if (update?.nextPepperVersion)
      record.refreshPepperVersion = update.nextPepperVersion;
    if (update?.authorization) {
      record.roles = update.authorization.roles;
      record.permissions = update.authorization.permissions;
      record.claims = update.authorization.claims;
    }
    record.lastUsedAt = now;
    return { status: "rotated" as const, record: structuredClone(record) };
  }
  async get(id: string) {
    const record = this.records.get(id);
    return record ? structuredClone(record) : undefined;
  }
  async list(scope: string, userId: string) {
    return [...this.records.values()]
      .filter((record) => record.scope === scope && record.userId === userId)
      .map((record) => structuredClone(record));
  }
  async revokeOwned(id: string, scope: string, userId: string) {
    const record = this.records.get(id);
    if (
      !record ||
      record.scope !== scope ||
      record.userId !== userId ||
      record.status !== "active"
    )
      return false;
    record.status = "revoked";
    return true;
  }
  async revokeFamily(familyId: string) {
    let count = 0;
    for (const record of this.records.values())
      if (record.familyId === familyId && record.status === "active") {
        record.status = "revoked";
        count += 1;
      }
    return count;
  }
  async revokeAll(scope: string, userId: string) {
    let count = 0;
    for (const record of this.records.values())
      if (
        record.scope === scope &&
        record.userId === userId &&
        record.status === "active"
      ) {
        record.status = "revoked";
        count += 1;
      }
    return count;
  }
}

export interface MemoryRateLimiterOptions {
  limit?: number;
  windowMs?: number;
}
export class MemoryRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, number[]>();
  private readonly limit: number;
  private readonly windowMs: number;
  constructor(options: MemoryRateLimiterOptions = {}) {
    this.limit = options.limit ?? 5;
    this.windowMs = options.windowMs ?? 60_000;
  }
  async consume(input: RateLimitRequest) {
    const timestamp = input.now.getTime();
    const cutoff = timestamp - this.windowMs;
    let retryAfterMs = 0;
    for (const key of input.keys) {
      const bucketKey = `${input.operation}:${key}`;
      const entries = (this.buckets.get(bucketKey) ?? []).filter(
        (entry) => entry > cutoff,
      );
      if (entries.length >= this.limit)
        retryAfterMs = Math.max(
          retryAfterMs,
          entries[0]! + this.windowMs - timestamp,
        );
    }
    if (retryAfterMs > 0) return { allowed: false as const, retryAfterMs };
    for (const key of input.keys) {
      const bucketKey = `${input.operation}:${key}`;
      const entries = (this.buckets.get(bucketKey) ?? []).filter(
        (entry) => entry > cutoff,
      );
      entries.push(timestamp);
      this.buckets.set(bucketKey, entries);
    }
    return { allowed: true as const };
  }
}
