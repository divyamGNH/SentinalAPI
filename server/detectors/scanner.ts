import { Detector, RequestContext, DetectionResult } from '../types';
import { Request } from 'express';

const SCANNER_PATTERN = /(sqlmap|nikto|nmap|dirbuster|gobuster|python-requests)/i;

export const scannerDetector: Detector = {
  name: 'Scanner / Attack Tool',
  check(req: Request, context: RequestContext): DetectionResult | null {
    const userAgent = req.headers['user-agent'] || '';

    if (SCANNER_PATTERN.test(userAgent)) {
      return {
        detectorName: this.name,
        severity: 'high',
        matchedPayload: userAgent,
        reason: `Known attack tool User-Agent detected: '${userAgent}'`,
        evidence: { rule: 'scanner-header-v1', field: 'header.User-Agent', explanation: 'Matched a known tool signature in the client header.' },
      };
    }

    return null;
  }
};
