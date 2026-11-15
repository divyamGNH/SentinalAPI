import { RequestContext } from './types';
import type { DecisionEvidence } from '../shared/defense';

type Bucket = { context: RequestContext; touched: number };
const buckets = new Map<string, Bucket>();
export const thresholds = { bruteForce: 5, bruteWindowMs: 30_000, spraying: 5, sprayWindowMs: 60_000, flood: 50, floodWindowMs: 10_000, blockMs: 30_000, enumeration: 15, enumWindowMs: 20_000 };

export function counterEvidence(rule: string, field: string, explanation: string, count: number, limit: number, windowMs: number, unit: string): DecisionEvidence {
  return { rule, field, explanation, counter: { count, limit, windowSeconds: windowMs / 1000, unit } };
}

export function getDetectionState(namespace: string, ip: string): RequestContext {
  let bucket = buckets.get(namespace);
  if (!bucket) {
    if (buckets.size >= 10_000) throw new Error('Detection state capacity reached');
    bucket = { touched: Date.now(), context: { ip, failedLoginsByIp: new Map(), credStuffingLogins: new Map(), requestCountsByIp: new Map(), notFoundCountsByIp: new Map(), blockedIps: new Set(), blockedUntil: 0 } };
    buckets.set(namespace, bucket);
  }
  bucket.touched = Date.now();
  return bucket.context;
}

export function releaseDetectionState(prefix: string) {
  for (const key of buckets.keys()) if (key.startsWith(prefix)) buckets.delete(key);
}

setInterval(() => {
  for (const [key, bucket] of buckets) if (Date.now() - bucket.touched > 120_000) buckets.delete(key);
}, 30_000).unref();
