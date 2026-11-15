import { Detector } from '../types';
import { Request } from 'express';
import { requestPayloads } from '../payloads';

const SQLI_PATTERN = /(?:['"]\s*(?:or|and)\s+\S+\s*=)|\bunion\s+(?:all\s+)?select\b|;\s*(?:drop|delete|update|insert|select)\b|\b(?:sleep|benchmark|pg_sleep)\s*\(|['"]\s*--|\bor\s+\d+\s*=\s*\d+/i;

export function matchesSqlSignature(normalized: string) {
  return SQLI_PATTERN.test(normalized);
}

export const sqlInjectionDetector: Detector = {
  name: 'SQL Injection',
  check(req: Request) {
    const input = requestPayloads(req).find(item => matchesSqlSignature(item.value));
    if (!input) return null;

    return {
      detectorName: this.name,
      severity: 'high',
      matchedPayload: input.sensitive ? '[redacted]' : input.value.slice(0, 50),
      reason: input.sensitive ? 'SQL Injection pattern found in a redacted field' : `SQL Injection pattern found: '${input.value.slice(0, 20)}...'`,
      evidence: {
        rule: 'sql-signature-v1',
        field: input.field,
        explanation: 'Matched a SQL signature in normalized input.',
      },
    };
  },
};
