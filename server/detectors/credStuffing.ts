import { Detector, RequestContext, DetectionResult } from '../types';
import { Request } from 'express';
import { createHash } from 'crypto';
import { validLabLogin } from '../labAuth';
import { counterEvidence, thresholds } from '../detectionState';

export const credStuffingDetector: Detector = {
  name: 'Credential Stuffing',
  check(req: Request, context: RequestContext): DetectionResult | null {
    if (req.path === '/login' && req.method === 'POST') {
      const username = req.body?.username;
      const password = req.body?.password;
      
      if (typeof username !== 'string' || typeof password !== 'string') return null;

      // Only track if it's a failure (toy app logic)
      if (validLabLogin(req.body)) return null;
      const passwordKey = createHash('sha256').update(password).digest('hex');

      let ipMap = context.credStuffingLogins.get(context.ip);
      if (!ipMap) {
        ipMap = new Map<string, Map<string, number>>();
        context.credStuffingLogins.set(context.ip, ipMap);
      }

      let usernames = ipMap.get(passwordKey);
      if (!usernames) {
        usernames = new Map<string, number>();
        ipMap.set(passwordKey, usernames);
      }

      const now = Date.now();
      for (const [key, attempts] of ipMap) {
        for (const [user, at] of attempts) if (now - at >= thresholds.sprayWindowMs) attempts.delete(user);
        if (!attempts.size && key !== passwordKey) ipMap.delete(key);
      }
      usernames.set(username, now);

      const evidence = counterEvidence('lab-password-spray-v1', 'body.username + password group', 'Counts distinct usernames receiving the same password. Password values are redacted.', usernames.size, thresholds.spraying, thresholds.sprayWindowMs, 'distinct usernames');
      if (usernames.size >= thresholds.spraying) {
        return {
          detectorName: this.name,
          severity: 'high',
          matchedPayload: '[password redacted]',
          reason: `Credential stuffing detected (password tried on ${usernames.size} distinct users)`,
          evidence,
        };
      }
      req.decisionEvidence?.push(evidence);
    }
    return null;
  }
};
