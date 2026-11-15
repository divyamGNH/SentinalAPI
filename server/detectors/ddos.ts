import { Detector, RequestContext, DetectionResult } from '../types';
import { Request } from 'express';
import { counterEvidence, thresholds } from '../detectionState';

export const ddosDetector: Detector = {
  name: 'Request Flood / DDoS',
  check(req: Request, context: RequestContext): DetectionResult | null {
    let counts = context.requestCountsByIp.get(context.ip) || [];
    const now = Date.now();

    counts.push(now);
    // Keep last 10 seconds
    counts = counts.filter(t => now - t < thresholds.floodWindowMs);
    context.requestCountsByIp.set(context.ip, counts);

    const evidence = counterEvidence('request-rate-v1', 'Request frequency', 'Counts recent requests in this detection scope.', counts.length, thresholds.flood, thresholds.floodWindowMs, 'requests');
    if (counts.length >= thresholds.flood) {
      context.blockedUntil = now + thresholds.blockMs;

      return {
        detectorName: this.name,
        severity: 'high',
        reason: `Request flood detected (${counts.length} requests in 10s)`,
        evidence,
      };
    }

    req.decisionEvidence?.push(evidence);
    return null;
  }
};
