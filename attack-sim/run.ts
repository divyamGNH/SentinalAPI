import 'dotenv/config';
import { readFile, mkdir, writeFile } from 'fs/promises';
import { resolve, join } from 'path';
import { SimulationRun, SimulationOptions, scenarioNames } from '../shared/simulation';
import { reportCsv, reportHtml } from '../shared/report';
import { buildPlan, parseOptions } from './catalog';

async function main() {
  const args = process.argv.slice(2);
  const help = `
SentinelAPI local security simulation
  npm run sim -- [options]
  --scenario all|sqli,xss,command,brute,spraying,ssrf,upload,scanner,traversal,enumeration,flood,benign
  --profile standard|extended    Standard: controlled regression suite; extended: raw SecLists probes
  --password-limit 20            Dictionary candidates, 5–200 (25-attempt independent trials)
  --wordlist ./passwords.txt      Optional custom newline-separated list, up to 1,000 entries
  --output ./reports             Save JSON, CSV, and HTML evidence
  --list                         Show planned scenarios without sending requests
  --all                          Run the suite (also the default)
  --help                         Show this help

Environment: API_BASE_URL (loopback only), SENTINEL_USERNAME, SENTINEL_PASSWORD
The username/password authenticate the runner. Dictionary guesses target the separate local /login lab.
`;
  if (args.includes('--help')) { console.log(help); return; }
  const values: Record<string,string> = {};
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (['--all','--list'].includes(flag)) continue;
    if (!['--scenario','--profile','--password-limit','--wordlist','--output'].includes(flag) || !args[i+1] || args[i+1].startsWith('--')) throw new Error('Unknown/missing argument: ' + flag + '\n' + help);
    values[flag] = args[++i];
  }
  const input: Partial<SimulationOptions> = {
    profile: (values['--profile'] || 'standard') as 'standard' | 'extended',
    scenarios: values['--scenario'] && values['--scenario'] !== 'all' ? values['--scenario'].split(',') : undefined,
    passwordLimit: Number(values['--password-limit'] || 20)
  };
  if (values['--wordlist']) input.passwords = (await readFile(resolve(values['--wordlist']), 'utf8')).split(/\r?\n/).filter(Boolean);
  const options = parseOptions(input);
  const plan = buildPlan(options);
  console.log('\nSentinelAPI — local security simulation');
  console.log('Source:', plan.source);
  console.table(options.scenarios.map(key => ({ scenario: key, detector: scenarioNames[key], requests: plan.cases.filter(item => item.scenario === key).length })));
  console.log(`Total: ${plan.cases.length} test requests; ${plan.passwordCount} password candidates (redacted).`);
  if (args.includes('--list')) return;

  const target = new URL(process.env.API_BASE_URL || 'http://localhost:3000');
  if (!['http:','https:'].includes(target.protocol) || !['localhost','127.0.0.1','[::1]'].includes(target.hostname) || target.username || target.password || target.pathname !== '/' || target.search || target.hash) throw new Error('API_BASE_URL must be a loopback origin such as http://localhost:3000');
  const base = target.origin;
  async function api(path: string, token?: string, method = 'GET', body?: unknown) {
    const response = await fetch(base + path, { method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) }, body: body ? JSON.stringify(body) : undefined, redirect: 'error', signal: AbortSignal.timeout(15_000) });
    const data = await response.json() as any;
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${data.error || data.status || 'API request failed'}`);
    return data;
  }
  await api('/health');
  const login = await api('/auth/login', undefined, 'POST', { username: process.env.SENTINEL_USERNAME || 'admin', password: process.env.SENTINEL_PASSWORD || 'sentinel123' });
  let run: SimulationRun = await api('/simulations', login.token, 'POST', options);
  console.log(`Run: ${run.id}\nTarget: ${base}\n`);
  const cancel = () => { void api(`/simulations/${run.id}/cancel`, login.token, 'POST').catch(() => undefined); };
  process.once('SIGINT', cancel);
  let seen = 0;
  const deadline = Date.now() + 180_000;
  while (run.status === 'running') {
    if (Date.now() > deadline) { cancel(); throw new Error('Run exceeded three minutes; cancellation requested. Check Simulations in the dashboard.'); }
    await new Promise(resolve => setTimeout(resolve, 500));
    run = await api(`/simulations/${run.id}`, login.token);
    for (const row of run.report?.cases.slice(seen) || []) {
      console.log(`${row.passed ? 'PASS' : 'FAIL'} ${row.scenario.padEnd(12)} ${row.name} | HTTP ${row.status} | ${row.latencyMs} ms | alerts: ${row.alertIds.join(',') || 'none'}`);
    }
    seen = run.progress;
  }
  process.removeListener('SIGINT', cancel);
  const output = resolve(values['--output'] || 'reports');
  await mkdir(output, { recursive: true });
  const stem = join(output, `sentinel-${run.id}`);
  await writeFile(stem + '.json', JSON.stringify(run, null, 2));
  await writeFile(stem + '.csv', reportCsv(run));
  await writeFile(stem + '.html', reportHtml(run));
  console.table(run.report?.coverage.map(row => ({ scenario: row.scenario, cases: row.total, pass: row.passed, fail: row.failed })) || []);
  console.log(`Status: ${run.status} | Passed: ${run.report?.passed || 0} | Failed: ${run.report?.failed || 0} | False positives: ${run.report?.falsePositives || 0} | Missing expected alerts: ${run.report?.missedDetections || 0}`);
  if (run.error) console.error(run.error);
  console.log('Reports:', stem + '.json', stem + '.csv', stem + '.html');
  console.log('A missed signature indicates detector coverage, not proof that code executed. See HTML report for evidence.');
  if (run.status !== 'completed' || run.report?.failed) process.exitCode = 1;
}

main().catch(error => { console.error((error as Error).message); process.exitCode = 1; });
