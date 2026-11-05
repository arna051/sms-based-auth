import { safeEqual } from './crypto.js';
import type { ChallengeRecord, ChallengeStore, SessionRecord, SessionStore } from './types.js';

export class MemoryChallengeStore implements ChallengeStore {
  private records = new Map<string, ChallengeRecord>();
  async createReplacing(record: ChallengeRecord) { const old = this.records.get(record.key); if (old?.state === 'active') old.state = 'superseded'; this.records.set(record.key, structuredClone(record)); }
  async consumeAttempt(key: string, hash: string, now: Date) {
    const record = this.records.get(key); if (!record || record.state !== 'active') return { status: 'missing' as const };
    if (record.expiresAt <= now) { record.state = 'expired'; return { status: 'expired' as const }; }
    if (safeEqual(record.codeHash, hash)) { record.state = 'verified'; return { status: 'verified' as const, record: structuredClone(record) }; }
    record.attempts++; if (record.attempts >= record.maxAttempts) { record.state = 'locked'; return { status: 'locked' as const }; }
    return { status: 'invalid' as const };
  }
}
export class MemorySessionStore<TClaims extends Record<string, unknown> = Record<string, unknown>> implements SessionStore<TClaims> {
  private records = new Map<string, SessionRecord<TClaims>>();
  async create(record: SessionRecord<TClaims>) { this.records.set(record.id, structuredClone(record)); }
  async rotate(id: string, hash: string, next: string, now: Date) { const r = this.records.get(id); if (!r || r.status !== 'active' || r.expiresAt <= now) return 'invalid'; if (r.spentRefreshHashes.some(spent => safeEqual(spent, hash))) { r.status = 'compromised'; return 'reused'; } if (!safeEqual(r.refreshHash, hash)) return 'invalid'; r.spentRefreshHashes.push(r.refreshHash); r.refreshHash = next; r.lastUsedAt = now; return 'rotated'; }
  async get(id: string) { const r = this.records.get(id); return r ? structuredClone(r) : undefined; }
  async list(userId: string) { return [...this.records.values()].filter(r => r.userId === userId).map(r => structuredClone(r)); }
  async revoke(id: string) { const r = this.records.get(id); if (r) r.status = 'revoked'; }
  async revokeAll(userId: string) { let count = 0; for (const r of this.records.values()) if (r.userId === userId && r.status === 'active') { r.status = 'revoked'; count++; } return count; }
}
