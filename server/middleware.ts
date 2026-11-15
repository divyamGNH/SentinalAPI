import { Request, Response, NextFunction } from 'express';
import { Detector, DetectionResult } from './types';
import { insertAlert } from './db';
import { counterEvidence, getDetectionState, thresholds } from './detectionState';
import { simulationLane } from './simulationContext';
import { sqlInjectionDetector } from './detectors/sqli';
import { xssDetector } from './detectors/xss';
import { pathTraversalDetector } from './detectors/pathTraversal';
import { cmdInjectionDetector } from './detectors/cmdInjection';
import { bruteforceDetector } from './detectors/bruteforce';
import { credStuffingDetector } from './detectors/credStuffing';
import { ddosDetector } from './detectors/ddos';
import { ssrfDetector } from './detectors/ssrf';
import { fileUploadDetector } from './detectors/fileUpload';
import { scannerDetector } from './detectors/scanner';

const detectors: Detector[] = [ddosDetector, scannerDetector, sqlInjectionDetector, xssDetector,
  pathTraversalDetector, cmdInjectionDetector, bruteforceDetector, credStuffingDetector, ssrfDetector, fileUploadDetector];

export async function sentinelMiddleware(req: Request, res: Response, next: NextFunction) {
  if (req.path === '/alerts' || req.path.startsWith('/alerts/')) return next();
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const runId = req.header('x-sentinel-run');
  const caseId = req.header('x-sentinel-case');
  const lane = runId && caseId ? simulationLane(runId, req.authUser!.id, caseId) : undefined;
  if ((runId || caseId) && !lane) return res.status(400).json({ error: 'Invalid or finished simulation context' });
  if (lane) req.decisionEvidence = [];
  const attachDecisions = () => {
    if (req.decisionEvidence?.length) {
      res.setHeader('x-sentinel-decisions', Buffer.from(JSON.stringify(req.decisionEvidence)).toString('base64url'));
    }
  };
  const namespace = lane ? `simulation:${runId}:${lane}` : `user:${req.authUser!.id}:${ip}`;
  const context = getDetectionState(namespace, ip);
  const log = async (result: DetectionResult) => {
    const alert = await insertAlert({
      user_id: req.authUser!.id, source_ip: ip, detector_name: result.detectorName,
      severity: result.severity, matched_payload: result.matchedPayload || '',
      request_path: req.path === '/login' ? req.path : req.originalUrl.slice(0, 2000), reason: result.reason,
      simulation_id: runId,
      simulation_case_id: caseId,
      decision_evidence: result.evidence,
    });
    if (result.evidence) req.decisionEvidence?.push(result.evidence);
    res.setHeader('x-sentinel-detector', result.detectorName);
    res.setHeader('x-sentinel-alert-id', String(alert.id));
    req.app.emit('new-alert', req.authUser!.id);
  };

  try {
    if (context.blockedUntil > Date.now()) {
      res.setHeader('Retry-After', Math.ceil((context.blockedUntil - Date.now()) / 1000));
      req.decisionEvidence?.push({ rule: 'request-cooldown-v1', field: 'Request frequency', explanation: 'The temporary rate limit is still active.' });
      attachDecisions();
      return res.status(429).json({ error: 'Request rate exceeded. Temporary cooldown.' });
    }
    if (context.blockedUntil) { context.blockedUntil = 0; context.requestCountsByIp.clear(); }

    for (const detector of detectors) {
      const result = await detector.check(req, context);
      if (result) {
        await log(result);
        attachDecisions();
        return res.status(detector === ddosDetector ? 429 : 403).json({ error: 'Request blocked by security policy', detector: result.detectorName });
      }
    }

    // Enumeration is known only after route resolution. Log before returning the 404,
    // making the alert visible when a test receives its response.
    if (!['/login', '/search', '/fetch', '/upload'].includes(req.path) && !/^\/profile\/[^/]+$/.test(req.path)) {
      const now = Date.now();
      const counts = [...(context.notFoundCountsByIp.get(ip) || []), now].filter(t => now - t < thresholds.enumWindowMs);
      context.notFoundCountsByIp.set(ip, counts);
      const evidence = counterEvidence('missing-routes-v1', 'Request path', 'Counts recent requests for missing routes. The response remains HTTP 404.', counts.length, thresholds.enumeration, thresholds.enumWindowMs, 'missing routes');
      if (counts.length >= thresholds.enumeration) {
        await log({ detectorName: 'Endpoint Enumeration', severity: 'medium', reason: `Endpoint enumeration detected (${counts.length} 404s in 20s)`, evidence });
        context.notFoundCountsByIp.set(ip, []);
      } else req.decisionEvidence?.push(evidence);
      attachDecisions();
      return res.status(404).json({ error: 'Endpoint not found' });
    }
    attachDecisions();
    next();
  } catch (error) {
    console.error('Security inspection failed:', error);
    return res.status(503).json({ error: 'Security inspection unavailable; request rejected' });
  }
}
