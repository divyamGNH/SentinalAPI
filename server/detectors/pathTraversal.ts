import { Detector } from '../types';
import { Request } from 'express';
import { requestPayloads } from '../payloads';

const PATH_TRAVERSAL_PATTERN = /(?:\.\.|%2e%2e)(?:\/|\\|%2f)|\/etc\/passwd|C:\\Windows/i;

export const pathTraversalDetector: Detector = {
  name: 'Path Traversal',
  check(req: Request) {
    const input = requestPayloads(req, true).find(item => PATH_TRAVERSAL_PATTERN.test(item.value));
    if (!input) return null;

    return {
      detectorName: this.name,
      severity: 'high',
      matchedPayload: input.sensitive ? '[redacted]' : input.value.slice(0, 50),
      reason: input.sensitive ? 'Path Traversal pattern found in a redacted field' : `Path Traversal pattern found: '${input.value.slice(0, 20)}...'`,
      evidence: {
        rule: 'path-traversal-v1',
        field: input.field,
        explanation: 'Matched a traversal or sensitive path signature.',
      },
    };
  },
};
