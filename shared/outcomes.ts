import type { CaseResult } from './simulation';

export function outcome(row: CaseResult): { label: string; tone: string; detail: string } {
  if (row.error || !row.status) return { label: 'Request error', tone: 'danger', detail: row.error || 'The request did not receive a response.' };
  if (row.status === 429) return { label: 'Rate limited', tone: 'warning', detail: 'The security layer rejected this request during a temporary cooldown.' };
  if (row.status === 403) return { label: 'Blocked', tone: row.benign ? 'danger' : 'success', detail: row.benign ? 'This input was expected to be allowed, but the security layer blocked it. Review the input and its expectation.' : 'The security layer stopped this request before it reached the demo endpoint.' };
  if (row.expectedDetector && !row.detected.includes(row.expectedDetector)) return { label: 'Detection gap', tone: 'danger', detail: 'The expected detector did not record an alert for this input. This is not proof of a successful exploit.' };
  if (row.status === 401) return { label: 'Login rejected', tone: 'neutral', detail: 'The demo login rejected incorrect credentials. No security threshold has necessarily been reached yet.' };
  if (row.status === 404) return { label: row.detected.length ? 'Detected · 404' : 'Route not found', tone: row.detected.length ? 'warning' : 'neutral', detail: row.detected.length ? 'The route does not exist, and the request also produced a security alert.' : 'The requested route does not exist.' };
  if (row.status >= 500) return { label: 'Service error', tone: 'danger', detail: 'The backend could not complete this request.' };
  return { label: 'Allowed', tone: row.benign ? 'success' : 'neutral', detail: row.benign ? 'Normal traffic reached the endpoint without being blocked.' : 'The request reached the demo endpoint. Inspect the expected outcome and detector evidence below.' };
}

export function runStats(rows: CaseResult[]) {
  return {
    blocked: rows.filter(r => r.status === 403).length,
    limited: rows.filter(r => r.status === 429).length,
    allowed: rows.filter(r => r.status >= 200 && r.status < 300).length,
    gaps: rows.filter(r => r.expectedDetector && !r.detected.includes(r.expectedDetector)).length,
    alerts: new Set(rows.flatMap(r => r.alertIds)).size,
  };
}
