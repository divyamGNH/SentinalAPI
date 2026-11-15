result.detected = [...new Set(matching.map(a => a.detector_name))];
result.alertIds = [...new Set(matching.map(a => a.id))];
result.reasons = [...new Set(matching.map(a => a.reason))];
result.matchedInputs = [...new Set(matching.map(a => a.matched_payload).filter(Boolean))];
result.passed = !result.error && result.expectedStatus.includes(result.status) &&
  (!result.expectedDetector || result.detected.includes(result.expectedDetector)) && (!result.benign || matching.length === 0);
