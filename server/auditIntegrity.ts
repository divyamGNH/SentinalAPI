import { createHmac, timingSafeEqual } from 'node:crypto';
import type { AuditVerification } from '../shared/defense';

export interface AuditCheckpoint {
  legacy_through: string;
  head_id: string;
  head_tag: string;
  event_count: number;
  signature: string;
}

export interface SignedAuditEntry {
  id: string;
  payload: string;
  integrity_tag: string | null;
}

const key = process.env.AUDIT_INTEGRITY_SECRET || process.env.JWT_SECRET || 'sentinel-development-secret-change-me';
const hmac = (content: unknown) => createHmac('sha256', key).update(JSON.stringify(content)).digest('hex');

function equalTag(actual: string | null, expected: string) {
  return actual !== null && /^[a-f0-9]{64}$/.test(actual)
    && timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
}

export function signAuditEntry(parent: string, id: string, payload: string) {
  return hmac(['sentinel.audit.entry.v1', parent, id, payload]);
}

function checkpointSignature(checkpoint: Omit<AuditCheckpoint, 'signature'>) {
  return hmac(['sentinel.audit.checkpoint.v1', checkpoint.legacy_through, checkpoint.head_id, checkpoint.head_tag, checkpoint.event_count]);
}

export function signCheckpoint(checkpoint: Omit<AuditCheckpoint, 'signature'>): AuditCheckpoint {
  return { ...checkpoint, signature: checkpointSignature(checkpoint) };
}

export const validCheckpoint = (checkpoint: AuditCheckpoint) => equalTag(checkpoint.signature, checkpointSignature(checkpoint));

export function initialCheckpoint(legacyThrough: string): AuditCheckpoint {
  return signCheckpoint({ legacy_through: legacyThrough, head_id: legacyThrough, head_tag: '', event_count: 0 });
}

export function verifyAuditEntries(checkpoint: AuditCheckpoint | undefined, entries: SignedAuditEntry[]): AuditVerification {
  const legacyThrough = checkpoint?.legacy_through ?? '0';
  if (!checkpoint || !validCheckpoint(checkpoint)) {
    return { valid: false, checked: 0, legacyThrough, problem: 'The signed checkpoint is missing or invalid.' };
  }

  let parent = '';
  let lastId = legacyThrough;
  let checked = 0;
  for (const entry of entries) {
    const expected = signAuditEntry(parent, entry.id, entry.payload);
    if (!equalTag(entry.integrity_tag, expected)) {
      return { valid: false, checked, legacyThrough, problem: `Audit event #${entry.id} failed verification.` };
    }
    parent = expected;
    lastId = entry.id;
    checked++;
  }
  if (checked !== checkpoint.event_count || lastId !== checkpoint.head_id || parent !== checkpoint.head_tag) {
    return { valid: false, checked, legacyThrough, problem: 'The audit records no longer match the signed checkpoint.' };
  }
  return { valid: true, checked, legacyThrough };
}

export function demonstrateAuditIntegrity(change: 'edit' | 'delete') {
  const initial = initialCheckpoint('0');
  const entries: SignedAuditEntry[] = [];
  let parent = initial.head_tag;
  for (const [index, payload] of ['Experiment started', 'Alert acknowledged', 'Experiment completed'].entries()) {
    const id = String(index + 1);
    parent = signAuditEntry(parent, id, payload);
    entries.push({ id, payload, integrity_tag: parent });
  }
  const checkpoint = signCheckpoint({ ...initial, head_id: '3', head_tag: parent, event_count: entries.length });
  const altered = entries.map(entry => ({ ...entry }));
  if (change === 'edit') altered[1].payload = 'Alert resolved';
  else altered.pop();

  return {
    original: verifyAuditEntries(checkpoint, entries),
    altered: verifyAuditEntries(checkpoint, altered),
    originalActions: entries.map(entry => entry.payload),
    alteredActions: altered.map(entry => entry.payload),
  };
}
