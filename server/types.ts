import { Request } from 'express';
import type { DecisionEvidence } from '../shared/defense';

declare global {
  namespace Express {
    interface Request {
      decisionEvidence?: DecisionEvidence[];
    }
  }
}

export type Severity = 'low' | 'medium' | 'high';

export interface DetectionResult {
  detectorName: string;
  severity: Severity;
  matchedPayload?: string;
  reason: string;
  evidence?: DecisionEvidence;
}

export interface RequestContext {
  ip: string;
  failedLoginsByIp: Map<string, number[]>; // ip -> array of timestamps
  credStuffingLogins: Map<string, Map<string, Map<string, number>>>; // IP -> password hash -> username/timestamp
  requestCountsByIp: Map<string, number[]>; // ip -> array of timestamps
  notFoundCountsByIp: Map<string, number[]>; // ip -> array of timestamps
  blockedIps: Set<string>; // ips that are temporarily blocked
  blockedUntil: number;
}

export interface Detector {
  name: string;
  check(req: Request, context: RequestContext): DetectionResult | null | Promise<DetectionResult | null>;
}
