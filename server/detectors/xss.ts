import { Detector } from '../types';
import { Request } from 'express';
import { requestPayloads } from '../payloads';

const XSS_PATTERN = /<\s*script\b|\bon(?:error|load|click|focus|mouseover)\s*=|javascript\s*:|<\s*(?:iframe|object|embed)\b[^>]*(?:src|data)\s*=/i;

export const xssDetector: Detector = {
  name: 'XSS',
  check(req: Request) {
    const input = requestPayloads(req).find(item => XSS_PATTERN.test(item.value));
    if (!input) return null;

    return {
      detectorName: this.name,
      severity: 'high',
      matchedPayload: input.sensitive ? '[redacted]' : input.value.slice(0, 50),
      reason: input.sensitive ? 'XSS pattern found in a redacted field' : `XSS pattern found: '${input.value.slice(0, 20)}...'`,
      evidence: {
        rule: 'xss-signature-v1',
        field: input.field,
        explanation: 'Matched an active markup signature in normalized input.',
      },
    };
  },
};
