import { readFileSync } from 'fs';
import { resolve } from 'path';
import { SimulationCase, SimulationOptions, scenarioNames } from '../shared/simulation';

export const corpus = JSON.parse(readFileSync(resolve(process.cwd(), 'attack-sim/fixtures/seclists.json'), 'utf8')) as {
  revision: string; repository: string; passwords: string[]; sqli: string[]; xss: string[];
};

export function parseOptions(input: Partial<SimulationOptions>): SimulationOptions {
  const profile = input.profile || 'standard';
  if (!['standard', 'extended'].includes(profile)) throw new Error('Profile must be standard or extended');
  const scenarios = input.scenarios || Object.keys(scenarioNames);
  if (!Array.isArray(scenarios) || !scenarios.length || scenarios.some(key => !Object.hasOwn(scenarioNames, key))) throw new Error('Unknown scenario');
  const passwordLimit = input.passwordLimit ?? 20;
  if (input.presentation !== undefined && typeof input.presentation !== 'boolean') throw new Error('Presentation mode must be a boolean');
  if (input.probe && (scenarios.length !== 1 || !['sqli', 'xss', 'command', 'traversal', 'ssrf', 'scanner'].includes(scenarios[0]) || typeof input.probe.value !== 'string' || !input.probe.value.trim() || input.probe.value.length > 2000 || !['block', 'allow'].includes(input.probe.expect))) throw new Error('Custom input needs one supported scenario, 1–2,000 characters, and a block/allow expectation');
  if (!Number.isInteger(passwordLimit) || passwordLimit < 5 || passwordLimit > 200) throw new Error('Password limit must be between 5 and 200');
  if (input.passwords && (!Array.isArray(input.passwords) || input.passwords.length > 1000 || input.passwords.some(p => typeof p !== 'string' || !p.length || p.length > 256))) throw new Error('Wordlist must contain at most 1,000 nonempty passwords, up to 256 characters each');
  return { profile, scenarios: [...new Set(scenarios)], passwordLimit, passwords: input.passwords, presentation: input.presentation === true, probe: input.probe };
}

export function buildPlan(options: SimulationOptions) {
  if (options.probe) {
    const scenario = options.scenarios[0];
    const detector = { sqli: 'SQL Injection', xss: 'XSS', command: 'Command Injection', traversal: 'Path Traversal', ssrf: 'SSRF Attempt', scanner: 'Scanner / Attack Tool' }[scenario];
    const blocked = options.probe.expect === 'block';
    const item: SimulationCase = {
      id: 'case-custom', scenario, lane: 'custom', name: 'Your custom input',
      method: scenario === 'scanner' || scenario === 'ssrf' ? 'GET' : 'POST',
      path: scenario === 'ssrf' ? `/fetch?url=${encodeURIComponent(options.probe.value)}` : '/search',
      body: scenario === 'scanner' || scenario === 'ssrf' ? undefined : { input: options.probe.value },
      headers: scenario === 'scanner' ? { 'User-Agent': options.probe.value } : undefined,
      expectedStatus: [blocked ? 403 : 200], expectedDetector: blocked ? detector : undefined, benign: !blocked,
    };
    return { cases: [item], passwordCount: 0, source: 'User-provided local probe; expected outcome selected by the user' };
  }
  const cases: SimulationCase[] = [];
  const add = (scenario: string, item: Omit<SimulationCase, 'id' | 'scenario' | 'lane'> & { lane?: string }) => {
    cases.push({ ...item, id: `case-${cases.length + 1}`, scenario, lane: item.lane || scenario });
  };
  const query = (path: string, value: string) => `${path}${encodeURIComponent(value)}`;
  const injection = (scenario: string, payloads: string[], detector: string, community = false) => payloads.forEach((value, index) => {
    add(scenario, { lane: `${scenario}-${community ? 'community-' : ''}${Math.floor(index / 25)}`, name: `${detector} ${community ? 'SecLists probe' : 'payload'} ${index + 1}`, method: index % 3 === 0 ? 'POST' : 'GET', path: index % 3 === 0 ? '/search' : query('/search?q=', value), body: index % 3 === 0 ? { filter: { items: [value] } } : undefined, expectedStatus: [403], expectedDetector: detector });
  });

  ['hello world', "O'Reilly", 'select a color', 'rock & roll', '1 + 1 = 2', 'report-2026.csv', 'The cat is sleeping', 'https://example.com/help'].forEach((value, index) => add('benign', { name: `Normal search ${index + 1}`, method: 'GET', path: query('/search?q=', value), expectedStatus: [200], benign: true }));
  add('benign', { name: 'Nested JSON search', method: 'POST', path: '/search', body: { filters: { names: ['Alice', 'Bob'] } }, expectedStatus: [200], benign: true });
  add('benign', { name: 'Valid lab login', method: 'POST', path: '/login', body: { username: 'admin', password: 'password123' }, expectedStatus: [200], benign: true });
  add('benign', { name: 'Normal text upload', method: 'POST', path: '/upload', file: { name: 'notes.txt', type: 'text/plain', bytes: [...Buffer.from('Meeting notes')] }, expectedStatus: [200], benign: true });
  add('benign', { name: 'Public fetch simulation', method: 'GET', path: '/fetch?url=https%3A%2F%2Fexample.com', expectedStatus: [200], benign: true });

  injection('sqli', ["' OR 1=1--", "' UNION SELECT NULL--", '1 UNION ALL SELECT NULL', "'; DROP TABLE demo--", "' AND 'a'='a", '1 OR 2=2', 'SLEEP(1)', "' OR 'x'='x", '%27%20OR%201%3D1--', '%2527%2520OR%25201%253D1--', 'UNION SELECT 1', '1; SELECT 1'], 'SQL Injection');
  injection('xss', ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', '<input onfocus=alert(1)>', 'javascript:alert(1)', '<ScRiPt>alert(1)</ScRiPt>', '<img src=x onerror = alert(1)>', '%3Cscript%3Ealert(1)%3C/script%3E', '&#60;script&#62;alert(1)&#60;/script&#62;', '<iframe src="https://example.invalid"></iframe>'], 'XSS');
  ['../../etc/passwd', '..\\..\\Windows\\system.ini', '%2e%2e%2fetc%2fpasswd', '%252e%252e%252fetc%252fpasswd', '../../../config.json', '/etc/passwd'].forEach((p, i) => add('traversal', { name: `Traversal variant ${i + 1}`, method: 'GET', path: query('/search?q=', p), expectedStatus: [403], expectedDetector: 'Path Traversal' }));
  injection('command', ['; whoami', '| id', '&& pwd', '$(whoami)', '`id`', '; uname -a', '\nwhoami', '; echo sentinel-lab', '%3B%20whoami', '| ls'], 'Command Injection');

  const passwords = [...new Set(options.passwords || corpus.passwords)].filter(value => value !== 'password123').slice(0, options.passwordLimit);
  if (passwords.length < 5) throw new Error('Wordlist needs at least five unique non-lab passwords');
  passwords.forEach((password, i) => add('brute', { lane: `brute-${Math.floor(i / 25)}`, name: `Dictionary attempt ${i + 1} [redacted]`, method: 'POST', path: '/login', body: { username: 'admin', password }, expectedStatus: [i % 25 < 4 ? 401 : 403], expectedDetector: i % 25 < 4 ? undefined : 'Brute-Force Login' }));
  const sprayPassword = passwords[0];
  for (let i = 0; i < 10; i++) add('spraying', { name: `Password spray user ${i + 1}`, method: 'POST', path: '/login', body: { username: `lab-user-${i}`, password: sprayPassword }, expectedStatus: [i < 4 ? 401 : 403], expectedDetector: i < 4 ? undefined : 'Credential Stuffing' });
  ['http://127.0.0.1/', 'http://localhost/', 'http://10.0.0.1/', 'http://172.16.0.1/', 'http://192.168.1.1/', 'http://169.254.169.254/', 'http://[::1]/', 'http://2130706433/'].forEach((url, i) => add('ssrf', { name: `Internal target ${i + 1}`, method: 'GET', path: query('/fetch?url=', url), expectedStatus: [403], expectedDetector: 'SSRF Attempt' }));
  [Buffer.from([0x4d,0x5a,0,1]), Buffer.from('<?php echo 1;'), Buffer.from('#!/bin/sh\n'), Buffer.from([0x7f,0x45,0x4c,0x46])].forEach((buffer, i) => add('upload', { name: `Executable signature ${i + 1}`, method: 'POST', path: '/upload', file: { name: `image-${i}.png`, type: 'image/png', bytes: [...buffer] }, expectedStatus: [403], expectedDetector: 'Malicious File Upload' }));
  ['sqlmap/1.0', 'Nikto/2.0', 'nmap', 'gobuster', 'dirbuster', 'python-requests/2.0'].forEach(agent => add('scanner', { name: `Scanner header ${agent}`, method: 'GET', path: '/search?q=hello', headers: { 'User-Agent': agent }, expectedStatus: [403], expectedDetector: 'Scanner / Attack Tool' }));
  for (let i = 0; i < 15; i++) add('enumeration', { name: `Missing endpoint ${i + 1}`, method: 'GET', path: `/lab-missing-${i}`, expectedStatus: [404], expectedDetector: i === 14 ? 'Endpoint Enumeration' : undefined });
  for (let i = 0; i < 60; i++) add('flood', { name: `Flood request ${i + 1}`, method: 'GET', path: '/search?q=load-test', concurrent: true, expectedStatus: [200,429] });
  add('flood', { name: 'Cooldown rejects subsequent request', method: 'GET', path: '/search?q=cooldown', expectedStatus: [429] });
  add('flood', { name: 'Cooldown expires; normal request recovers', method: 'GET', path: '/search?q=recovered', delayMs: 31_000, expectedStatus: [200], benign: true });
  if (options.profile === 'extended') {
    injection('sqli', corpus.sqli.slice(0, 60), 'SQL Injection', true);
    injection('xss', corpus.xss.slice(0, 60), 'XSS', true);
  }
  const selected = cases.filter(item => options.scenarios.includes(item.scenario));
  // Preserve unique case IDs while keeping community batches separate from baseline counters.
  return { cases: selected, passwordCount: passwords.length, source: `SecLists@${corpus.revision}${options.passwords ? ' + custom password list' : ' (first 1,000 common passwords bundled)'}` };
}
