import test from 'node:test';
import assert from 'node:assert/strict';
import type { Request } from 'express';
import { demonstrateAuditIntegrity, initialCheckpoint, signAuditEntry, signCheckpoint, verifyAuditEntries } from '../server/auditIntegrity';
import { compareSqlRules } from '../server/ruleComparison';
import { sqlInjectionDetector } from '../server/detectors/sqli';
import { bruteforceDetector } from '../server/detectors/bruteforce';
import { getDetectionState, releaseDetectionState } from '../server/detectionState';

test('comparison detects the normal apostrophe false positive and retains all expected matches in the fixed suite', () => {
  const { rows } = compareSqlRules();
  const apostrophe = rows.find(row => row.title.includes("O'Reilly"));
  assert.equal(apostrophe?.expected, false);
  assert.equal(apostrophe?.before, true);
  assert.equal(apostrophe?.after, false);
  assert.ok(rows.some(row => row.expected));
  assert.equal(rows.filter(row => row.expected !== row.after).length, 0);
});

test('audit signatures cover edits, missing final events, and checkpoint changes', () => {
  for (const change of ['edit', 'delete'] as const) {
    const result = demonstrateAuditIntegrity(change);
    assert.equal(result.original.valid, true);
    assert.equal(result.altered.valid, false);
  }
  const tag = signAuditEntry('', '41', 'event detail');
  const checkpoint = signCheckpoint({ ...initialCheckpoint('40'), head_id: '41', head_tag: tag, event_count: 1 });
  const entries = [{ id: '41', payload: 'event detail', integrity_tag: tag }];
  assert.equal(verifyAuditEntries(checkpoint, entries).valid, true);
  assert.equal(verifyAuditEntries({ ...checkpoint, event_count: 0 }, []).valid, false);
});

test('decision details describe measured thresholds and redact sensitive matched fields', async () => {
  const key = 'test:decision-evidence';
  const state = getDetectionState(key, '127.0.0.1');
  try {
    for (let count = 1; count <= 5; count++) {
      const req = { path: '/login', method: 'POST', body: { username: 'demo', password: 'synthetic-invalid' }, decisionEvidence: [] } as unknown as Request;
      const result = await bruteforceDetector.check(req, state);
      const evidence = result?.evidence ?? req.decisionEvidence?.[0];
      assert.equal(evidence?.counter?.count, count);
      assert.equal(evidence?.counter?.limit, 5);
      assert.equal(Boolean(result), count === 5);
    }
    const req = { body: { password: 'UNION SELECT [redacted-test-value]' } } as Request;
    const sensitive = await sqlInjectionDetector.check(req, state);
    assert.equal(sensitive?.matchedPayload, '[redacted]');
    assert.equal(sensitive?.evidence?.field, 'Sensitive request field');
    assert.ok(!JSON.stringify(sensitive).includes('redacted-test-value'));
  } finally {
    releaseDetectionState(key);
  }
});
