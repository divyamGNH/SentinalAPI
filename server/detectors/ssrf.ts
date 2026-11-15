import { Detector, RequestContext, DetectionResult } from '../types';
import { Request } from 'express';

export const ssrfDetector: Detector = {
  name: 'SSRF Attempt',
  check(req: Request, context: RequestContext): DetectionResult | null {
    if (req.path === '/fetch' && req.method === 'GET') {
      const urlStr = req.query.url;
      if (typeof urlStr !== 'string') return null;

      try {
        const urlObj = new URL(urlStr);
        const host = urlObj.hostname.toLowerCase().replace(/^\[|\]$/g, '');

        // SSRF Target checking
        const isLocalhost = host === 'localhost' || host.endsWith('.localhost') || /^127\./.test(host) || host === '0.0.0.0' || host === '::1' || host === '::';
        const isPrivateV6 = /^(?:fc|fd|fe[89ab])/i.test(host) || /^::ffff:(?:7f|a00:|c0a8:)/i.test(host);
        const isCloudMetadata = host === '169.254.169.254';
        
        // Basic private IP regex (10.x, 172.16-31.x, 192.168.x)
        const isPrivateIp = /^(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+)$/.test(host);

        if (isLocalhost || isCloudMetadata || isPrivateIp || isPrivateV6) {
          return {
            detectorName: this.name,
            severity: 'high',
            matchedPayload: host,
            reason: `SSRF attempt to internal/private target: ${host}`,
            evidence: { rule: 'internal-host-v1', field: 'query.url', explanation: 'The parsed hostname matches a restricted destination category.' },
          };
        }
      } catch (e) {
        // Invalid URL, ignore or could be flagged as malformed
      }
    }
    return null;
  }
};
