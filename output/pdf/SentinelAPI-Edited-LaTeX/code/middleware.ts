for (const detector of detectors) {
  const result = await detector.check(req, context);
  if (result) {
    await log(result);
    attachDecisions();
    return res.status(detector === ddosDetector ? 429 : 403).json({ error: 'Request blocked by security policy', detector: result.detectorName });
  }
}
