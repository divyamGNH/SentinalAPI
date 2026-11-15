import test from 'node:test';
import assert from 'node:assert/strict';
import { Request } from 'express';
import { getDetectionState, releaseDetectionState } from '../server/detectionState';
import { sqlInjectionDetector } from '../server/detectors/sqli';
import { xssDetector } from '../server/detectors/xss';
import { cmdInjectionDetector } from '../server/detectors/cmdInjection';
import { bruteforceDetector } from '../server/detectors/bruteforce';
import { credStuffingDetector } from '../server/detectors/credStuffing';
import { ddosDetector } from '../server/detectors/ddos';
import { ssrfDetector } from '../server/detectors/ssrf';
import { buildPlan, parseOptions } from '../attack-sim/catalog';
import { reportHtml, reportCsv, requestEvidence } from '../shared/report';
import { SimulationRun, CaseResult } from '../shared/simulation';
import { outcome, runStats } from '../shared/outcomes';

const request = (body: unknown = {}, query = {}, path = '/search') => ({ body, query, params: {}, originalUrl: path, path, method: 'POST', headers: {} }) as Request;
const context = (key: string) => getDetectionState(`test:${key}`, '127.0.0.1');
test.after(() => releaseDetectionState('test:'));

test('nested JSON and encoded payloads are inspected while ordinary apostrophes are allowed', async () => {
  assert.ok(await sqlInjectionDetector.check(request({ filters: [{ q: '%2527%2520OR%25201%253D1--' }] }), context('sql')));
  assert.equal(await sqlInjectionDetector.check(request({ q: "O'Reilly" }), context('sql')), null);
  assert.ok(await xssDetector.check(request({ q: '&#60;script&#62;alert(1)' }), context('xss')));
  assert.ok(await cmdInjectionDetector.check(request({ q: '\nwhoami' }), context('command')));
});

test('brute-force threshold, expiry, successful login reset, and user separation', async () => {
  const state = context('brute');
  for (let i = 0; i < 4; i++) assert.equal(await bruteforceDetector.check(request({ username: 'admin', password: `wrong${i}` }, {}, '/login'), state), null);
  assert.ok(await bruteforceDetector.check(request({ username: 'admin', password: 'wrong-last' }, {}, '/login'), state));
  assert.equal(context('other-user').failedLoginsByIp.size, 0);
  assert.equal(await bruteforceDetector.check(request({ username: 'admin', password: 'password123' }, {}, '/login'), state), null);
  assert.equal(state.failedLoginsByIp.size, 0);
  state.failedLoginsByIp.set('127.0.0.1:admin', Array(5).fill(Date.now() - 31_000));
  assert.equal(await bruteforceDetector.check(request({ username: 'admin', password: 'wrong' }, {}, '/login'), state), null);
});

test('password spraying counts unique users, expires old attempts, and redacts passwords', async () => {
  const state = context('spray');
  for (let i = 0; i < 4; i++) assert.equal(await credStuffingDetector.check(request({ username: 'same-user', password: 'secret' }, {}, '/login'), state), null);
  for (let i = 0; i < 3; i++) assert.equal(await credStuffingDetector.check(request({ username: `user${i}`, password: 'secret' }, {}, '/login'), state), null);
  const result = await credStuffingDetector.check(request({ username: 'fifth-user', password: 'secret' }, {}, '/login'), state);
  assert.equal(result?.matchedPayload, '[password redacted]');
  assert.ok(!JSON.stringify([...state.credStuffingLogins.get('127.0.0.1')!.keys()]).includes('secret'));
  for (const users of state.credStuffingLogins.get('127.0.0.1')!.values()) for (const name of users.keys()) users.set(name, Date.now() - 61_000);
  assert.equal(await credStuffingDetector.check(request({ username: 'new-user', password: 'secret' }, {}, '/login'), state), null);
});

test('flood starts at request 50 and sets a finite cooldown', async () => {
  const state = context('flood');
  for (let i = 0; i < 49; i++) assert.equal(await ddosDetector.check(request(), state), null);
  assert.ok(await ddosDetector.check(request(), state));
  assert.ok(state.blockedUntil > Date.now());
  assert.ok(state.blockedUntil <= Date.now() + 30_000);
});

test('SSRF URL normalization catches integer loopback and IPv6', async () => {
  for (const url of ['http://2130706433/', 'http://[::1]/', 'http://[fd00::1]/']) {
    const req = request({}, { url }, '/fetch'); req.method = 'GET';
    assert.ok(await ssrfDetector.check(req, context('ssrf')));
  }
});

test('standard/extended plan counts, unique cases, custom wordlist validation', () => {
  const standard = buildPlan(parseOptions({}));
  assert.equal(standard.cases.length, 175);
  assert.equal(new Set(standard.cases.map(item => item.id)).size, 175);
  assert.equal(buildPlan(parseOptions({ profile: 'extended' })).cases.length, 295);
  assert.throws(() => parseOptions({ scenarios: ['unknown'] }));
  assert.throws(() => parseOptions({ passwordLimit: 10000 }));
  assert.throws(() => buildPlan(parseOptions({ passwords: ['one'] })));
});

test('downloaded reports escape script content and spreadsheet formulas', () => {
  const run = { id: 'test', status: 'completed', report: { total: 1, cases: [{ name: '<script>alert(1)</script>', scenario: 'xss', method: 'GET', path: '=1+1', expectedStatus: [403], status: 200, detected: [], alertIds: [], latencyMs: 1, passed: false }], coverage: [] } } as unknown as SimulationRun;
  assert.ok(!reportHtml(run).includes('<script>'));
  assert.ok(reportHtml(run).includes('&lt;script&gt;'));
  assert.ok(reportCsv(run).includes("'=1+1"));
  const loginCase = buildPlan(parseOptions({ scenarios: ['brute'] })).cases[0];
  const evidence = requestEvidence(loginCase);
  assert.ok(evidence.includes('[redacted]'));
  assert.ok(!evidence.includes('"password":"password"'));
});

test('custom probes keep the target local, preserve expectations, and reject unsupported configurations', () => {
  const plan = buildPlan(parseOptions({ scenarios: ['sqli'], presentation: true, probe: { value: "' OR 1=1--", expect: 'block' } }));
  assert.equal(plan.cases.length, 1);
  assert.equal(plan.cases[0].path, '/search');
  assert.deepEqual(plan.cases[0].expectedStatus, [403]);
  assert.equal(plan.cases[0].expectedDetector, 'SQL Injection');
  const control = buildPlan(parseOptions({ scenarios: ['sqli'], probe: { value: "O'Reilly", expect: 'allow' } })).cases[0];
  assert.equal(control.benign, true);
  assert.equal(control.expectedDetector, undefined);
  assert.deepEqual(control.expectedStatus, [200]);
  const ssrf = buildPlan(parseOptions({ scenarios: ['ssrf'], probe: { value: 'http://127.0.0.1/', expect: 'block' } })).cases[0];
  assert.ok(ssrf.path.startsWith('/fetch?url='));
  assert.throws(() => parseOptions({ scenarios: ['flood'], probe: { value: 'test', expect: 'block' } }));
  assert.throws(() => parseOptions({ scenarios: ['sqli','xss'], probe: { value: 'test', expect: 'block' } }));
  assert.throws(() => parseOptions({ scenarios: ['sqli'], probe: { value: 'x'.repeat(2001), expect: 'block' } }));
  assert.throws(() => parseOptions({ presentation: 'yes' as unknown as boolean }));
});

test('actual outcomes stay separate from expectations and shared alerts are counted once', () => {
  const row: CaseResult = { id: 'one', scenario: 'sqli', name: 'probe', method: 'POST', path: '/search', expectedStatus: [403], expectedDetector: 'SQL Injection', status: 200, detected: [], alertIds: [], latencyMs: 2, passed: false, benign: false };
  assert.equal(outcome(row).label, 'Detection gap');
  assert.equal(outcome({ ...row, status: 403, detected: ['SQL Injection'], passed: true }).label, 'Blocked');
  assert.equal(outcome({ ...row, status: 401, expectedDetector: undefined, passed: true }).label, 'Login rejected');
  assert.equal(outcome({ ...row, status: 404, expectedDetector: undefined, detected: ['Endpoint Enumeration'] }).label, 'Detected · 404');
  assert.equal(outcome({ ...row, status: 403, benign: true }).tone, 'danger');
  const flood = { ...row, status: 429, alertIds: [12], detected: ['Request Flood / DDoS'], expectedDetector: 'Request Flood / DDoS' };
  assert.equal(runStats([flood, { ...flood, id: 'two' }]).alerts, 1);
  assert.equal(runStats([flood, { ...flood, id: 'two' }]).limited, 2);
});
