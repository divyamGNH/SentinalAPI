import { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { ArrowLeft, ArrowRight, Check, FlaskConical, History, Shield, X } from 'lucide-react';
import { reviewLabels, reviewVerdicts } from '../../shared/defense';
import type { AuditVerification, DecisionEvidence, ReviewSummary, ReviewVerdict, RuleComparison } from '../../shared/defense';
import { scenarioNames } from '../../shared/simulation';
import type { Alert } from './types';
import type { Connection } from './defenseApi';
import { requestDefense as request, saveReview } from './defenseApi';
import './defense.css';

type Navigate = (path: string) => void;

function useEvidence<T>({ api, token }: Connection, path: string, refresh = 0) {
  const [state, setState] = useState<{ path: string; data?: T; error?: string }>();
  useEffect(() => {
    const controller = new AbortController();
    request<T>(api, token, path, { signal: controller.signal }).then(data => {
      if (!controller.signal.aborted) setState({ path, data });
    }).catch(error => {
      if (!controller.signal.aborted) setState({ path, error: error.message });
    });
    return () => controller.abort();
  }, [api, token, path, refresh]);
  return state?.path === path ? state : undefined;
}

function Notice({ children, error = false }: { children: ReactNode; error?: boolean }) {
  return <div className={error ? 'error-box' : 'panel muted small'} role={error ? 'alert' : 'status'}>{children}</div>;
}

export function DecisionDetails({ evidence }: { evidence: DecisionEvidence[] }) {
  if (!evidence.length) return null;
  return <details className="decision-details">
    <summary>Explain this decision</summary>
    <div className="decision-evidence">
      {evidence.map((item, index) => <article key={item.rule + index}>
        <code>{item.rule}</code>
        <p>{item.explanation}</p>
        <p className="muted small">Inspected field <strong>{item.field}</strong></p>
        {item.counter && <div className="counter-evidence">
          <strong>{item.counter.count} / {item.counter.limit}</strong>
          <span>{item.counter.unit} in {item.counter.windowSeconds}s</span>
          <meter aria-label={item.counter.unit + ' against threshold'} min={0} max={item.counter.limit}
            value={Math.min(item.counter.count, item.counter.limit)} />
          <small>{item.counter.count >= item.counter.limit ? 'Threshold reached' : 'Below threshold'}</small>
        </div>}
      </article>)}
    </div>
  </details>;
}

export function AlertReview({
  alert, canReview, onReview,
}: { alert: Alert; canReview: boolean; onReview: (alert: Alert, verdict: ReviewVerdict) => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const verdict = alert.review_verdict ?? 'needs_review';
  async function change(value: ReviewVerdict) {
    setBusy(true);
    setError('');
    try { await onReview(alert, value); }
    catch (problem) { setError(problem instanceof Error ? problem.message : 'Unable to save review.'); }
    finally { setBusy(false); }
  }
  if (!canReview) return <span className="label neutral">{reviewLabels[verdict]}</span>;
  return <div className="review-control">
    <label>Review verdict
      <select disabled={busy} value={verdict} aria-label={'Review verdict for alert #' + alert.id}
        onChange={event => void change(event.target.value as ReviewVerdict)}>
        {reviewVerdicts.map(value => <option key={value} value={value}>{reviewLabels[value]}</option>)}
      </select>
    </label>
    {error && <span className="danger-text small" role="alert">{error}</span>}
  </div>;
}

export function ReviewBreakdown(props: Connection & { scope: string; userId: string; refresh: number }) {
  const params = new URLSearchParams({ scope: props.scope });
  if (props.scope === 'all' && props.userId !== 'all') params.set('userId', props.userId);
  const state = useEvidence<ReviewSummary[]>(props, '/defense/reviews?' + params, props.refresh);
  return <details className="panel review-breakdown">
    <summary>Review totals by detector</summary>
    <p className="muted small">Counts reflect analyst verdicts across all alerts in the selected account scope.</p>
    {state?.error ? <Notice error>{state.error}</Notice> : !state?.data ? <p role="status">Loading totals…</p>
      : !state.data.length ? <p className="muted">This scope has no alerts yet.</p>
      : <div className="defense-table"><table>
        <thead><tr><th>Detector</th><th>Confirmed</th><th>False positives</th><th>Needs review</th><th>Total</th></tr></thead>
        <tbody>{state.data.map(item => <tr key={item.detector}>
          <th scope="row">{displayDetector(item.detector)}</th><td>{item.confirmed}</td><td>{item.falsePositive}</td>
          <td>{item.needsReview}</td><td>{item.total}</td>
        </tr>)}</tbody>
      </table></div>}
  </details>;
}

function displayDetector(name: string) {
  return name === 'Credential Stuffing' ? 'Password spraying' : name;
}

export function DefenseLab(props: Connection & { admin: boolean; tab: string; navigate: Navigate }) {
  return <div className="screen-stack">
    <div className="page-heading"><div>
      <h2>Defense lab</h2>
      <p>Compare detection rules and verify the integrity of the audit trail.</p>
    </div></div>
    {props.admin && <div className="tabs">
      <button className={props.tab !== 'audit' ? 'selected' : ''} onClick={() => props.navigate('/defense')}>Rule comparison</button>
      <button className={props.tab === 'audit' ? 'selected' : ''} onClick={() => props.navigate('/defense/audit')}>Audit integrity</button>
    </div>}
    {props.admin && props.tab === 'audit' ? <AuditIntegrity {...props} /> : <Comparison {...props} />}
  </div>;
}

function Comparison(props: Connection) {
  const state = useEvidence<RuleComparison>(props, '/defense/comparison');
  const [changesOnly, setChangesOnly] = useState(false);
  if (!state) return <Notice>Loading the rule comparison…</Notice>;
  if (!state.data) return <Notice error>{state.error}</Notice>;
  const { rows, before, after, suite } = state.data;
  const versions = [
    { name: before, key: 'before' as const },
    { name: after, key: 'after' as const },
  ];
  const changed = rows.filter(row => row.change === 'improved');
  const regressed = rows.filter(row => row.change === 'regressed');
  const highlight = changed.find(row => !row.expected);
  return <>
    <div className="defense-intro">
      <FlaskConical size={22}/>
      <div><h3>{suite}</h3><p>Both rules evaluate the same {rows.length} labeled cases offline. The practice rule is for this comparison only.</p></div>
    </div>
    <div className="defense-grid">{versions.map(version => <section className="panel" key={version.key}>
      <p className="eyebrow">{version.key}</p><h3>{version.name}</h3>
      <dl className="defense-metrics">
        <div><dt>Suspicious cases matched</dt><dd>{rows.filter(row => row.expected && row[version.key]).length}/{rows.filter(row => row.expected).length}</dd></div>
        <div><dt>Normal cases flagged</dt><dd>{rows.filter(row => !row.expected && row[version.key]).length}/{rows.filter(row => !row.expected).length}</dd></div>
      </dl>
    </section>)}</div>
    <section className="panel">
      <div className="panel-heading">
        <div><h3>{changed.length} improved · {regressed.length} regressed</h3>
          {highlight && <p className="muted small">{highlight.title} was flagged before and allowed after.</p>}
        </div>
        <label className="checkbox-label"><input type="checkbox" checked={changesOnly}
          onChange={event => setChangesOnly(event.target.checked)}/> Show changes only</label>
      </div>
      <div className="defense-table"><table>
        <thead><tr><th>Test case</th><th>Expected</th><th>Before</th><th>After</th><th>Change</th></tr></thead>
        <tbody>{rows.filter(row => !changesOnly || row.change !== 'unchanged').map(row => <tr key={row.id}>
          <th scope="row">{row.title}</th>
          <td>{row.expected ? 'Flag' : 'Allow'}</td>
          <td><RuleOutcome actual={row.before} expected={row.expected}/></td>
          <td><RuleOutcome actual={row.after} expected={row.expected}/></td>
          <td><span className={'label ' + (row.change === 'improved' ? 'success' : row.change === 'regressed' ? 'danger' : 'neutral')}>{row.change}</span></td>
        </tr>)}</tbody>
      </table></div>
    </section>
  </>;
}

function RuleOutcome({ actual, expected }: { actual: boolean; expected: boolean }) {
  return <span className={'label ' + (actual === expected ? 'success' : 'danger')}>
    {actual === expected ? <Check size={13}/> : <X size={13}/>}
    {actual ? 'Flagged' : 'Allowed'}
  </span>;
}

interface AuditDemo {
  original: AuditVerification;
  altered: AuditVerification;
  originalActions: string[];
  alteredActions: string[];
}

function AuditIntegrity({ api, token }: Connection) {
  const [verification, setVerification] = useState<AuditVerification>();
  const [demo, setDemo] = useState<AuditDemo>();
  const [change, setChange] = useState<'edit' | 'delete'>('edit');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  async function run(demonstration: boolean) {
    setBusy(true);
    setError('');
    try {
      if (demonstration) {
        setDemo(await request<AuditDemo>(api, token, '/defense/audit/demo', {
          method: 'POST', body: JSON.stringify({ change }),
        }));
      } else setVerification(await request<AuditVerification>(api, token, '/defense/audit/verify'));
    } catch (problem) { setError(problem instanceof Error ? problem.message : 'Verification failed.'); }
    finally { setBusy(false); }
  }
  return <>
    {error && <Notice error>{error}</Notice>}
    <section className="panel integrity-panel">
      <div className="panel-heading">
        <div><h3>Verify live audit records</h3><p className="muted small">Check the chain of event signatures and its signed checkpoint.</p></div>
        <button className="btn primary" disabled={busy} onClick={() => void run(false)}><Shield size={16}/> Verify audit trail</button>
      </div>
      <div aria-live="polite">
        {verification && <><VerificationResult result={verification}/>
          <p className="muted small">{verification.legacyThrough === '0' ? 'Signing covers events from the start of the log.' : 'Events through #' + verification.legacyThrough + ' predate signing.'}</p>
        </>}
      </div>
    </section>
    <section className="panel integrity-panel">
      <div className="panel-heading"><div><h3>Tamper demonstration</h3>
        <p className="muted small">Change a copy of three sample records and compare the verification results.</p></div>
        <div className="inline-actions">
          <select aria-label="Tamper demonstration type" value={change} disabled={busy} onChange={event => {
            setDemo(undefined);
            setChange(event.target.value as 'edit' | 'delete');
          }}><option value="edit">Edit a record</option><option value="delete">Delete the last record</option></select>
          <button className="btn" disabled={busy} onClick={() => void run(true)}>Run demonstration</button>
        </div>
      </div>
      {demo && <div className="defense-grid" aria-live="polite">
        <div><h4>Original sample</h4><ol>{demo.originalActions.map(action => <li key={action}>{action}</li>)}</ol><VerificationResult result={demo.original}/></div>
        <div><h4>Altered sample</h4><ol>{demo.alteredActions.map(action => <li key={action}>{action}</li>)}</ol><VerificationResult result={demo.altered}/></div>
      </div>}
    </section>
  </>;
}

function VerificationResult({ result }: { result: AuditVerification }) {
  return <div className="verification-result">
    <span className={'label ' + (result.valid ? 'success' : 'danger')}>{result.valid ? 'Chain verified' : 'Integrity check failed'}</span>
    <p>{result.problem ?? (result.checked === 0 ? 'No signed events have been recorded yet.' : result.checked + ' signed events verified.')}</p>
  </div>;
}

interface IncidentSummary {
  id: string;
  username: string;
  status: string;
  scenarios: string[];
  alerts: number;
  unresolved: number;
  last_detection: string;
}

interface IncidentDetails extends Omit<IncidentSummary, 'alerts' | 'unresolved' | 'last_detection'> {
  created_at: string;
  completed_at: string | null;
  total: number;
  progress: number;
  alerts: Alert[];
  events: Array<{ id: string; username?: string; action: string; created_at: string; entity_id?: string; details: { verdict?: ReviewVerdict } }>;
}

const timestamp = (value: string) => new Date(value).toLocaleString();
const scenarioTitle = (keys: string[]) => keys.map(key => scenarioNames[key] ?? key).join(', ');

export function IncidentTimeline(props: Connection & { id?: string; canReview: boolean; navigate: Navigate }) {
  if (props.id) return <IncidentDetail {...props} id={props.id}/>;
  return <IncidentList {...props}/>;
}

function IncidentList(props: Connection & { navigate: Navigate }) {
  const state = useEvidence<IncidentSummary[]>(props, '/defense/incidents');
  if (!state) return <Notice>Loading incidents…</Notice>;
  if (!state.data) return <Notice error>{state.error}</Notice>;
  return <div className="screen-stack">
    <p className="muted small">Each incident groups the detections and investigator actions from one experiment.</p>
    {!state.data.length && <Notice>Incidents appear after an experiment records its first alert.</Notice>}
    <div className="recent-runs">
      {state.data.map(incident => <button key={incident.id} onClick={() => props.navigate('/activity/incidents/' + incident.id)}>
        <span className="icon-tile"><History size={18}/></span>
        <div><strong>{scenarioTitle(incident.scenarios)}</strong>
          <span>@{incident.username} · {timestamp(incident.last_detection)} · {incident.id.slice(0, 8)}</span>
        </div>
        <span className={'label ' + (incident.unresolved ? 'warning' : 'success')}>{incident.unresolved} of {incident.alerts} unresolved</span>
        <ArrowRight size={16}/>
      </button>)}
    </div>
  </div>;
}

function IncidentDetail(props: Connection & { id: string; canReview: boolean; navigate: Navigate }) {
  const [refresh, setRefresh] = useState(0);
  const state = useEvidence<IncidentDetails>(props, '/defense/incidents/' + props.id, refresh);
  const { api, token } = props;
  const review = useCallback(async (alert: Alert, verdict: ReviewVerdict) => {
    await saveReview({ api, token }, alert.id, verdict);
    setRefresh(value => value + 1);
  }, [api, token]);
  const incident = state?.data;
  if (!state) return <Notice>Loading incident…</Notice>;
  if (!incident) return <Notice error>{state.error}</Notice>;
  const actions = incident.events.map(event => {
    const labels: Record<string, string> = {
      simulation_started: 'Experiment started', simulation_completed: 'Experiment completed',
      simulation_failed: 'Experiment failed', simulation_cancelled: 'Experiment cancelled',
      alert_acknowledged: 'Alert acknowledged', alert_resolved: 'Alert resolved',
      alert_open: 'Alert reopened', alert_reviewed: 'Review verdict changed',
    };
    return {
      id: 'action-' + event.id, time: event.created_at, title: labels[event.action] ?? event.action,
      description: [
        event.username ? '@' + event.username : '',
        event.action.startsWith('alert_') ? 'Alert #' + event.entity_id : '',
        event.details.verdict ? reviewLabels[event.details.verdict] : '',
      ].filter(Boolean).join(' · '),
    };
  });
  if (!incident.events.some(event => event.action === 'simulation_started')) {
    actions.push({ id: 'start', time: incident.created_at, title: 'Experiment created', description: '@' + incident.username });
  }
  if (incident.completed_at && !incident.events.some(event => ['simulation_completed', 'simulation_failed', 'simulation_cancelled'].includes(event.action))) {
    actions.push({ id: 'end', time: incident.completed_at, title: 'Experiment ' + incident.status, description: incident.progress + ' requests recorded' });
  }
  const timeline: Array<{ id: string; time: string; title: string; description: string; alert?: Alert }> = [
    ...actions, ...incident.alerts.map(alert => ({
    id: 'alert-' + alert.id, time: alert.timestamp, title: displayDetector(alert.detector_name),
    description: alert.reason, alert,
    })),
  ].sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
  return <section className="panel incident-panel">
    <button className="text-btn" onClick={() => props.navigate('/activity/incidents')}><ArrowLeft size={15}/> All incidents</button>
    <div className="panel-heading">
      <div><h3>{scenarioTitle(incident.scenarios)}</h3>
        <p className="muted small">@{incident.username} · {incident.alerts.length} alerts · {incident.progress}/{incident.total} requests</p>
      </div>
      <button className="btn" onClick={() => props.navigate('/reports/' + incident.id)}>Open experiment <ArrowRight size={15}/></button>
    </div>
    <ol className="incident-timeline">
      {timeline.map(item => <li key={item.id}>
        <time dateTime={item.time}>{timestamp(item.time)}</time>
        <h4>{item.title}</h4><p>{item.description}</p>
        {item.alert && <>
          <div className="inline-actions">
            <span className="label neutral">#{item.alert.id}</span>
            <span className={'status-badge ' + item.alert.status}>{item.alert.status}</span>
            <AlertReview alert={item.alert} canReview={props.canReview} onReview={review}/>
          </div>
          {item.alert.decision_evidence && <DecisionDetails evidence={[item.alert.decision_evidence]}/>}
        </>}
      </li>)}
    </ol>
  </section>;
}
