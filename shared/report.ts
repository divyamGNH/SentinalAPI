import { scenarioNames } from './simulation';
import type { SimulationRun, SimulationCase } from './simulation';
import { outcome, runStats } from './outcomes';

export function requestEvidence(item: SimulationCase) {
  if (item.file) return `${item.file.name} (${item.file.type}), first bytes: ${item.file.bytes.slice(0,16).map(byte => byte.toString(16).padStart(2,'0')).join(' ')}`;
  if (item.body) return JSON.stringify(item.body, (key, value) => /password|token|authorization/i.test(key) ? '[redacted]' : value).slice(0,2000);
  if (item.headers?.['User-Agent']) return `User-Agent: ${item.headers['User-Agent']}`;
  return item.path;
}

export function reportCsv(run: SimulationRun) {
  const cell = (value: unknown) => {
    const text = String(value ?? '');
    const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
    return `"${safe.replace(/"/g, '""')}"`;
  };
  const rows = [['case','scenario','name','method','path','input','expected_http','actual_http','expected_detector','detected','alert_ids','latency_ms','outcome','expectation','detector_reason','response','error'], ...(run.report?.cases || []).map(item => [item.id,item.scenario,item.name,item.method,item.path,item.payload,item.expectedStatus.join('|'),item.status,item.expectedDetector,item.detected.join('|'),item.alertIds.join('|'),item.latencyMs,outcome(item).label,item.passed ? 'Matched' : 'Unexpected',item.reasons?.join('|'),item.responseBody,item.error])];
  return rows.map(row => row.map(cell).join(',')).join('\n');
}

export function reportHtml(run: SimulationRun) {
  const escape = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]!));
  const report = run.report;
  const stats = runStats(report?.cases || []);
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SentinelAPI experiment ${escape(run.id)}</title><style>body{font:15px system-ui;max-width:1400px;margin:40px auto;padding:0 24px;color:#142131}h1{margin-bottom:8px}.meta{color:#52627a}.stats{display:flex;flex-wrap:wrap;gap:24px;padding:24px;background:#edf7f3;border-radius:10px}table{border-collapse:collapse;width:100%;font-size:12px;margin:24px 0}td,th{border-bottom:1px solid #d8e2ed;text-align:left;padding:10px;overflow-wrap:anywhere;vertical-align:top}.pass{color:#087743}.fail{color:#bc2436}code{white-space:pre-wrap}small{color:#52627a}details{margin-top:8px} @media print{body{margin:0}details{display:block}}</style><h1>SentinelAPI — experiment results</h1><p class="meta">Run ${escape(run.id)} · User ${escape(run.username || run.user_id)} · ${escape(run.created_at)} · ${escape(run.status)}</p><div class="stats"><b>${run.progress || 0}/${run.total || report?.total || 0} requests completed</b><b>${stats.blocked} blocked</b><b>${stats.limited} rate limited</b><b>${stats.allowed} allowed</b><b class="fail">${stats.gaps} expected alerts missing</b><b>${stats.alerts} unique alerts</b></div><p>${report?.passed || 0} responses matched expectations; ${report?.failed || 0} differed. ${report?.falsePositives || 0} false positives. A matched expectation means the system behaved as predicted; it does not mean an attack succeeded.</p><p>Source: ${escape(report?.source)}. Duration: ${report?.durationMs || 0} ms. Password candidates: ${report?.passwordCount || 0} (values redacted).</p><p>This experiment measures rule-based inspection on local demo endpoints. Submitted SQL, scripts, and shell commands are not executed. Fetch is simulated. Flood traffic comes from one local host. A missing signature is a detection gap, not proof of successful exploitation. Extended inputs may contain incomplete syntax. Counts describe this run only.</p>${run.error ? `<p class="fail">${escape(run.error)}</p>` : ''}<h2>Scenarios</h2><table><tr><th>Scenario</th><th>Checked</th><th>As expected</th><th>Unexpected</th></tr>${(report?.coverage || []).map(row => `<tr><td>${escape(scenarioNames[row.scenario])}</td><td>${row.total}</td><td>${row.passed}</td><td>${row.failed}</td></tr>`).join('')}</table><h2>Request evidence</h2><table><tr><th>Request & input</th><th>Actual outcome</th><th>Security evidence</th><th>Expectation</th></tr>${(report?.cases || []).map(row => `<tr><td><b>${escape(row.name)}</b><br><small>${escape(scenarioNames[row.scenario])}</small><br><code>${escape(row.method)} ${escape(row.path)}</code><br><code>${escape(row.payload || '')}</code></td><td><b>${escape(outcome(row).label)}</b><br>HTTP ${row.status}<br>${row.latencyMs} ms${row.responseBody ? `<details><summary>API response</summary><code>${escape(row.responseBody)}</code></details>` : ''}</td><td>${escape(row.detected.join(', ') || 'No alert')}<br>Alert IDs: ${row.alertIds.join(', ') || 'None'}<br>${escape(row.reasons?.join('; ') || '')}</td><td class="${row.passed ? 'pass' : 'fail'}">${row.passed ? 'Matched' : 'Unexpected'}<br><small>Expected HTTP ${row.expectedStatus.join(' or ')}${row.expectedDetector ? ` + ${escape(row.expectedDetector)} alert` : ''}</small><br>${escape(row.error)}</td></tr>`).join('')}</table></html>`;
}
