import { Detector } from '../types';
import { Request } from 'express';
import { requestPayloads } from '../payloads';

const CMD_INJECTION_PATTERN = /(?:;|\||&&|`|\$\(|\n)\s*(?:\S*\/)?(?:rm|cat|whoami|ls|id|pwd|sleep|ping|curl|wget|uname|echo)\b/i;

export const cmdInjectionDetector: Detector = {
  name: 'Command Injection',
  check(req: Request) {
    const input = requestPayloads(req).find(item => CMD_INJECTION_PATTERN.test(item.value));
    if (!input) return null;

    return {
      detectorName: this.name,
      severity: 'high',
      matchedPayload: input.sensitive ? '[redacted]' : input.value.slice(0, 50),
      reason: input.sensitive ? 'Command Injection pattern found in a redacted field' : `Command Injection pattern found: '${input.value.slice(0, 20)}...'`,
      evidence: {
        rule: 'shell-signature-v1',
        field: input.field,
        explanation: 'Matched a shell syntax signature in normalized input.',
      },
    };
  },
};
