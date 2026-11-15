import { Detector, RequestContext, DetectionResult } from '../types';
import { Request } from 'express';
import { validLabLogin } from '../labAuth';
import { counterEvidence, thresholds } from '../detectionState';

export const bruteforceDetector: Detector = {
  name: 'Brute-Force Login',
  check(req: Request, context: RequestContext): DetectionResult | null {
    if (req.path === '/login' && req.method === 'POST') {
      const username = req.body?.username;
      const password = req.body?.password;
      
      if (typeof username !== 'string' || typeof password !== 'string') return null;

      const key = `${context.ip}:${username}`;
      let timestamps = context.failedLoginsByIp.get(key) || [];
      const now = Date.now();

      // We assume any password other than 'password123' is a failure for the toy app
      if (!validLabLogin(req.body)) {
        timestamps.push(now);
      } else {
        context.failedLoginsByIp.delete(key);
        return null;
      }

      // Keep only last 30 seconds
      timestamps = timestamps.filter(t => now - t < thresholds.bruteWindowMs);
      context.failedLoginsByIp.set(key, timestamps);

      const evidence = counterEvidence('lab-brute-force-v1', 'body.username', 'Counts failed logins for this username and source.', timestamps.length, thresholds.bruteForce, thresholds.bruteWindowMs, 'failed logins');
      if (timestamps.length >= thresholds.bruteForce) {
        return {
          detectorName: this.name,
          severity: 'high',
          matchedPayload: username,
          reason: `Brute-force detected for user '${username}' (${timestamps.length} fails in 30s)`,
          evidence,
        };
      }
      req.decisionEvidence?.push(evidence);
    }
    return null;
  }
};
