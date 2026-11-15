import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Activity, ArrowDown, ArrowLeft, ArrowRight, Check, ChevronRight, Download, FileText, FlaskConical, Layers, Pause, Play, Radio, RefreshCw, RotateCcw, Search, Send, Server, ShieldCheck, Square, Terminal, X } from 'lucide-react';
import type { SimulationRun } from '../../shared/simulation';
import { outcome, runStats, scenarios } from './labModel';
import { DecisionDetails } from './DefenseLab';

interface Catalog { enabled: boolean; revision: string; repository: string; passwords: number; sqlPayloads: number; xssPayloads: number }
interface Plan { total: number; cases: Array<{ id: string; name: string; method: string; path: string; payload: string }> }
type Props = { token: string; role: string; userId: number; api: string; scenario?: string; results?: boolean; runId?: string; navigate: (path: string) => void };
const when = (value: string) => new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

export function SimulationLab({ token, role, userId, api, scenario, results = false, runId, navigate }: Props) {
  const journey = useRef<HTMLElement>(null);
  const [profile, setProfile] = useState('standard');
  const [passwordLimit, setPasswordLimit] = useState(20);
  const [passwords, setPasswords] = useState<string[]>();
  const [wordlistName, setWordlistName] = useState('Bundled SecLists wordlist');
  const [presentation, setPresentation] = useState(true);
  const [custom, setCustom] = useState(false);
  const [customValue, setCustomValue] = useState('');
  const [expect, setExpect] = useState<'block' | 'allow'>('block');
  const [catalog, setCatalog] = useState<Catalog>();
  const [runs, setRuns] = useState<SimulationRun[]>([]);
  const [run, setRun] = useState<SimulationRun>();
  const [plan, setPlan] = useState<Plan>();
  const [error, setError] = useState('');
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [selectedId, setSelectedId] = useState('');
  const [follow, setFollow] = useState(true);
  const [replaying, setReplaying] = useState(false);
  const [phase, setPhase] = useState(3);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [group, setGroup] = useState('All');
  const request = useCallback(async (path: string, init?: RequestInit) => {
    const response = await fetch(api + path, { ...init, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...init?.headers } });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Unable to reach the API.');
    return data;
  }, [api, token]);
  const load = useCallback(async () => {
    try {
      const [history, source] = await Promise.all([request('/simulations'), request('/simulations/catalog')]);
      setRuns(history); setCatalog(source);
    } catch (err) { setError((err as Error).message); }
  }, [request]);
  useEffect(() => { void load(); }, [load, results, runId, scenario]);
  useEffect(() => {
    let active = true;
    setRun(undefined); setSelectedId(''); setReplaying(false); setFollow(true); setFilter('all'); setSearch(''); setError('');
    setCustom(false); setCustomValue(scenarios[scenario || '']?.example || '');
    if (runId) request(`/simulations/${runId}`).then(data => { if (active) setRun(data); }).catch(err => { if (active) setError(err.message); });
    else if (scenario) request('/simulations').then((history: SimulationRun[]) => {
      const current = history.find(item => item.status === 'running' && item.user_id === userId);
      if (active && current && (scenario === 'all' ? current.config.scenarios.length > 1 : current.config.scenarios.length === 1 && current.config.scenarios[0] === scenario)) setRun(current);
    }).catch(err => { if (active) setError(err.message); });
    return () => { active = false; };
  }, [request, runId, scenario, userId]);
  const selectedScenarios = useMemo(() => scenario === 'all' ? Object.keys(scenarios) : scenario && scenarios[scenario] ? [scenario] : [], [scenario]);
  useEffect(() => {
    let active = true;
    setPlan(undefined);
    if (selectedScenarios.length) request(`/simulations/plan?profile=${profile}&passwordLimit=${passwordLimit}&scenarios=${selectedScenarios.join(',')}`).then(data => { if (active) setPlan(data); }).catch(err => { if (active) setError(err.message); });
    return () => { active = false; };
  }, [passwordLimit, profile, request, selectedScenarios]);
  useEffect(() => {
    if (run?.status !== 'running') return;
    let active = true;
    const timer = setInterval(() => {
      request(`/simulations/${run.id}`).then(data => {
        if (!active) return;
        setRun(data); setError('');
        if (data.status !== 'running') { setStopping(false); void load(); }
      }).catch(err => { if (active) setError(err.message); });
    }, 500);
    return () => { active = false; clearInterval(timer); };
  }, [load, request, run?.id, run?.status]);
  const rows = useMemo(() => run?.report?.cases || [], [run?.report]);
  const row = (follow ? rows.at(-1) : rows.find(item => item.id === selectedId)) || rows[0];
  const rowIndex = row ? rows.findIndex(item => item.id === row.id) : -1;
  const focusedId = row?.id;
  useEffect(() => {
    if (!focusedId || run?.status !== 'running') return;
    setPhase(0);
    const timers = [1,2,3].map(step => setTimeout(() => setPhase(step), step * 140));
    return () => timers.forEach(clearTimeout);
  }, [focusedId, run?.status]);
  useEffect(() => {
    if (!replaying || !rows.length) return;
    const timer = setTimeout(() => {
      if (phase < 3) setPhase(phase + 1);
      else if (rowIndex < rows.length - 1) { setSelectedId(rows[rowIndex + 1].id); setPhase(0); }
      else setReplaying(false);
    }, 750);
    return () => clearTimeout(timer);
  }, [phase, replaying, rowIndex, rows]);
  const start = async () => {
    setError(''); setStarting(true); setReplaying(false); setFollow(true); setPhase(3);
    try {
      const data = await request('/simulations', { method: 'POST', body: JSON.stringify({ profile, passwordLimit, scenarios: selectedScenarios, passwords, presentation, probe: custom ? { value: customValue, expect } : undefined }) });
      setRun(data); await load();
    } catch (err) { setError((err as Error).message); }
    finally { setStarting(false); }
  };
  const cancel = async () => {
    setStopping(true);
    try { await request(`/simulations/${run!.id}/cancel`, { method: 'POST' }); }
    catch (err) { setError((err as Error).message); setStopping(false); }
  };
  const download = async (format: string) => {
    try {
      const response = await fetch(`${api}/simulations/${run!.id}/report?format=${format}`, { headers: { Authorization: `Bearer ${token}` } });
      if (!response.ok) throw new Error('Report download failed.');
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement('a'); link.href = url; link.download = `sentinel-${run!.id}.${format}`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) { setError((err as Error).message); }
  };
  const inspect = (id: string) => {
    setFollow(false); setSelectedId(id); setReplaying(false); setPhase(3);
    journey.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  const replay = () => {
    if (replaying) { setReplaying(false); setPhase(3); return; }
    setFollow(false); setSelectedId(rows[0]?.id || ''); setPhase(0); setReplaying(true);
    journey.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  const running = run?.status === 'running';
  const activeElsewhere = runs.find(item => item.status === 'running' && item.user_id === userId && item.id !== run?.id);
  const stats = runStats(rows);
  const info = scenarios[row?.scenario || scenario || ''];
  const chosen = scenarios[scenario || ''];
  const decision = row ? outcome(row) : undefined;
  const customSupported = ['sqli', 'xss', 'command', 'traversal', 'ssrf', 'scanner'].includes(scenario || '');
  const visibleRows = rows.filter(item => (filter === 'all' || (filter === 'gaps' ? !item.passed : filter === 'blocked' ? [403,429].includes(item.status) : item.status >= 200 && item.status < 300)) && `${item.name} ${item.path} ${item.detected.join(' ')}`.toLowerCase().includes(search.toLowerCase()));
  const history = <div className="history-grid">{runs.filter(item => !search || `${item.username} ${item.config.scenarios.map(key => scenarios[key]?.name).join(' ')} ${item.id}`.toLowerCase().includes(search.toLowerCase())).map(item => {
    const summary = runStats(item.report?.cases || []);
    return <button className="history-card" key={item.id} onClick={() => navigate(`/reports/${item.id}`)}><div className="split"><span className={`label ${item.status === 'running' ? 'accent' : item.status === 'completed' ? 'success' : 'warning'}`}>{item.status === 'running' ? 'Running' : item.status}</span><ChevronRight size={17}/></div><h3>{item.config.scenarios.length > 1 ? `${item.config.scenarios.length} scenarios` : scenarios[item.config.scenarios[0]]?.name || 'Simulation'}</h3><p>{when(item.created_at)} · @{item.username || item.user_id}</p><div className="history-numbers"><span><strong>{item.progress}/{item.total}</strong> requests</span><span><strong>{summary.blocked + summary.limited}</strong> stopped</span><span className={summary.gaps ? 'danger-text' : ''}><strong>{summary.gaps}</strong> missing alerts</span></div><div className="history-footer">{item.config.customProbe ? 'Custom input' : item.config.profile === 'extended' ? 'Extended probes' : 'Standard scenarios'}<code>{item.id.slice(0,8)}</code></div></button>;
  })}{!runs.length && <div className="empty-panel"><FileText size={30}/><h3>Your experiments will appear here.</h3><p>Run a scenario to save its requests, detector evidence, and results.</p><button className="btn" onClick={() => navigate('/simulations')}>Choose an attack <ArrowRight size={15}/></button></div>}</div>;

  if (results && !runId) return <div className="screen-stack"><div className="page-heading"><div><p className="eyebrow">Evidence, saved</p><h2>Every run has a story.</h2><p>Reopen an experiment, inspect its requests, or download a report.</p></div><button className="btn" onClick={load}><RefreshCw size={16}/>Refresh</button></div>{error && <div role="alert" className="error-box">{error}</div>}<label className="search-field"><Search size={17}/><input aria-label="Search runs" placeholder="Search by scenario, user, or run ID…" value={search} onChange={e => setSearch(e.target.value)}/></label>{history}</div>;
  if (!scenario && !runId) return <div className="screen-stack"><div className="page-heading"><div><p className="eyebrow">Attack playground</p><h2>Pick an attack. Follow the defense.</h2><p>Send real requests to the local API and see exactly how it responds.</p></div><span className="environment-tag"><span/>Local environment</span></div>{error && <div role="alert" className="error-box">{error}</div>}<div className="suite-banner"><div className="icon-tile"><Layers size={24}/></div><div><h3>Want the complete picture?</h3><p>Run all 11 attack scenarios plus normal traffic in one experiment.</p></div><button className="btn" onClick={() => navigate('/simulations/all')}>Full suite <ArrowRight size={16}/></button></div><div className="filter-pills" aria-label="Scenario categories">{['All', 'Injection', 'Authentication', 'Access', 'Reconnaissance', 'Availability', 'Control'].map(value => <button key={value} aria-pressed={group === value} className={group === value ? 'selected' : ''} onClick={() => setGroup(value)}>{value}</button>)}</div><div className="scenario-grid">{Object.entries(scenarios).filter(([, item]) => group === 'All' || item.group === group).map(([key, item], index) => <button className="scenario-card" key={key} onClick={() => navigate(`/simulations/${key}`)}><div className="split"><span className={`scenario-icon ${key === 'benign' ? 'green' : ''}`}>{key === 'brute' || key === 'spraying' ? <Terminal size={20}/> : key === 'flood' ? <Activity size={20}/> : key === 'benign' ? <ShieldCheck size={20}/> : <FlaskConical size={20}/>}</span><span className="muted small">{String(index + 1).padStart(2,'0')}</span></div><span className="card-category">{item.group}</span><h3>{item.name}</h3><p>{item.short}</p><span className="card-action">Open scenario <ArrowRight size={15}/></span></button>)}</div><div className="quiet-note"><ShieldCheck size={18}/><p>This lab inspects attack inputs without executing their SQL, scripts, or shell commands. All generated traffic stays on this computer.</p></div></div>;

  return <div className="screen-stack">
    <button className="back-link" onClick={() => navigate(results ? '/reports' : '/simulations')}><ArrowLeft size={15}/>{results ? 'All results' : 'All scenarios'}</button>
    <div className="page-heading"><div><p className="eyebrow">{results ? `Recorded experiment · ${run?.id.slice(0,8) || 'Loading'}` : chosen?.group || 'Complete experiment'}</p><h2>{results ? run?.config.scenarios.length === 1 ? scenarios[run.config.scenarios[0]]?.name : 'Full experiment results' : chosen?.name || 'Full security suite'}</h2><p>{results ? 'Actual responses and saved detector evidence. Replay any request below.' : chosen?.short || 'All attack scenarios and normal controls, with one combined report.'}</p></div>{results && running && <button className="btn danger-button" disabled={stopping} onClick={cancel}><Square size={15}/>{stopping ? 'Stopping…' : 'Stop experiment'}</button>}{run && <span className={`label ${running ? 'accent' : run.status === 'completed' ? 'success' : 'warning'}`}>{running && <Radio size={13}/>} {run.status}</span>}</div>
    {error && <div className="error-box" role="alert">{error}<button className="icon-button" aria-label="Dismiss error" onClick={() => setError('')}><X size={15}/></button></div>}
    {!results && <section className="experiment-setup panel"><div className="setup-intro"><span className="step-number">01</span><div><h3>Set up the experiment</h3><p>{chosen?.goal || 'Check detection, normal access, and threshold-based behavior across the API.'}</p></div></div><div className="setup-controls"><label>Payload collection<select value={profile} disabled={running || custom} onChange={e => setProfile(e.target.value)}><option value="standard">Standard · curated examples</option><option value="extended">Extended · community probes</option></select></label><label>Run speed<select value={presentation ? 'guided' : 'fast'} disabled={running} onChange={e => setPresentation(e.target.value === 'guided')}><option value="guided">Guided · watch each request</option><option value="fast">Fast · collect results</option></select></label>{selectedScenarios.some(key => ['brute','spraying'].includes(key)) && <label>Password attempts<input aria-label="Password attempts" type="number" min={5} max={200} value={passwordLimit} disabled={running} onChange={e => setPasswordLimit(Number(e.target.value))}/></label>}<div className="launch-control"><span className="muted small">{custom ? 1 : plan?.total ?? '…'} {custom || plan?.total === 1 ? 'request' : 'requests'} · {scenario === 'flood' || scenario === 'all' ? 'includes 30s recovery' : 'local API only'}</span>{running ? <button className="btn danger-button" disabled={stopping} onClick={cancel}><Square size={15}/>{stopping ? 'Stopping…' : 'Stop experiment'}</button> : <button className="btn primary" disabled={starting || Boolean(activeElsewhere) || !plan || role === 'viewer' || !catalog?.enabled || (custom && !customValue.trim())} onClick={start}><Play size={16}/>{starting ? 'Starting…' : run ? 'Run again' : 'Start experiment'}</button>}</div></div>
      {(customSupported || selectedScenarios.includes('brute')) && <details className="advanced-settings"><summary>Try your own input / advanced options</summary>{customSupported && <><label className="checkbox-label"><input type="checkbox" checked={custom} disabled={running} onChange={e => setCustom(e.target.checked)}/>Send my own input instead of the collection</label>{custom && <div className="custom-probe"><label>Input<textarea value={customValue} maxLength={2000} disabled={running} onChange={e => setCustomValue(e.target.value)}/></label><label>What should the detector do?<select value={expect} disabled={running} onChange={e => setExpect(e.target.value as 'block' | 'allow')}><option value="block">Block this input</option><option value="allow">Allow this input</option></select></label><p className="muted small">Your expectation is compared with the real response. An allowed probe does not mean its contents were executed.</p></div>}</>}{selectedScenarios.includes('brute') && <label>Custom password list (.txt)<input type="file" accept=".txt,text/plain" disabled={running} onChange={async e => {
        const file = e.target.files?.[0]; if (!file) { setPasswords(undefined); setWordlistName('Bundled SecLists wordlist'); return; }
        if (file.size > 256_000) { setError('Choose a wordlist smaller than 256 KB.'); return; }
        const values = [...new Set((await file.text()).split(/\r?\n/).filter(Boolean))];
        if (values.length < 5 || values.length > 1000 || values.some(value => value.length > 256)) { setError('Use 5–1,000 unique passwords, each at most 256 characters.'); return; }
        setPasswords(values); setWordlistName(file.name); setError('');
      }}/><span className="muted small">{wordlistName} · values are redacted in evidence</span>{passwords && <button type="button" className="text-btn" onClick={() => { setPasswords(undefined); setWordlistName('Bundled SecLists wordlist'); }}>Use bundled list</button>}</label>}</details>}
      {profile === 'extended' && !custom && <p className="setup-note">Adds 60 SQL and 60 XSS community probes when those scenarios are selected. Some may reveal missing signatures or trigger a different detector.</p>}
      {activeElsewhere && <p className="setup-note">Another experiment is still running. <button className="text-btn" onClick={() => navigate('/reports/' + activeElsewhere.id)}>Open running experiment <ArrowRight size={13}/></button></p>}
      {role === 'viewer' && <p className="setup-note">Your viewer account can inspect results. An analyst or administrator can start a run.</p>}
      {catalog && !catalog.enabled && <p className="error-box">Simulation is disabled on this API.</p>}
    </section>}
    <section ref={journey} className="panel journey-panel"><div className="panel-heading"><div><p className="eyebrow">{replaying ? 'Replay · saved evidence' : running ? 'Live · verified responses' : row ? 'Request walkthrough' : 'How this experiment works'}</p><h3>{row ? row.name : 'From input to outcome'}</h3></div>{rows.length > 0 && <button className="btn" disabled={running} title={running ? 'Replay is available after the run finishes.' : 'Replay saved responses'} onClick={replay}>{replaying ? <Pause size={15}/> : <RotateCcw size={15}/>} {replaying ? 'Pause replay' : 'Replay run'}</button>}</div>
      <div className={`request-flow ${running || replaying ? 'is-active' : ''}`}>
        {[{ icon: Send, title: 'Request sent', text: row ? `${row.method} ${row.path.split('?')[0]}` : chosen?.target || 'Local API endpoints' }, { icon: Search, title: 'Security inspection', text: row ? row.detected.join(', ') || 'No detector alert' : 'Normalize input · check rules' }, { icon: Server, title: 'API decision', text: decision ? `${decision.label} · HTTP ${row.status}` : 'Allow, block, or rate limit' }, { icon: FileText, title: 'Evidence saved', text: row ? `${row.alertIds.length} alert${row.alertIds.length === 1 ? '' : 's'} · ${Math.round(row.latencyMs)} ms` : 'Response + database alerts' }].map((step, index) => <div key={step.title} className={`flow-step ${row && (!(replaying || running) || phase >= index) ? 'reached' : ''} ${index === 2 && decision ? decision.tone : ''}`}><div className="flow-icon"><step.icon size={22}/><span>{index + 1}</span></div><h4>{step.title}</h4><p>{(replaying || running) && phase < index ? 'Visualizing…' : step.text}</p>{index < 3 && <ArrowRight className="flow-arrow" size={19}/>}</div>)}
      </div>
      <p className="flow-caption">{replaying ? 'A visual replay of recorded responses. No new requests are sent.' : running ? 'Results appear after each real response is checked against saved alerts. The diagram summarizes that evidence.' : 'The diagram explains the measured request path. It does not execute the submitted payload.'}</p>
      {running && <div className="run-progress"><div className="split"><span>{run.progress} of {run.total} requests received</span><strong>{Math.round(run.progress / run.total * 100)}%</strong></div><progress max={run.total} value={run.progress}/>{run.progress === run.total - 1 && run.config.scenarios.includes('flood') && <p className="muted small">Waiting for the cooldown to expire before checking recovery…</p>}</div>}
    </section>
    {row && ['brute','spraying','enumeration','flood'].includes(row.scenario) && <section className="panel behavior-panel"><div className="panel-heading"><div><p className="eyebrow">Behavior over multiple requests</p><h3>{row.scenario === 'brute' ? 'One account. Repeated password guesses.' : row.scenario === 'spraying' ? 'One password. Multiple demo accounts.' : row.scenario === 'enumeration' ? 'Repeated guesses for missing endpoints.' : 'A burst, a cooldown, then recovery.'}</h3></div><span className="label neutral">{rows.filter(item => item.scenario === row.scenario).length} recorded responses</span></div><div className="response-sequence">{rows.filter(item => item.scenario === row.scenario).map((item, index) => <button key={item.id} aria-label={`Inspect response ${index + 1}: HTTP ${item.status}`} title={`${item.name} · HTTP ${item.status}`} className={`response-tick ${item.status === 429 ? 'limited' : item.status === 403 ? 'blocked' : item.status === 200 ? 'allowed' : 'rejected'} ${row.id === item.id ? 'selected' : ''}`} onClick={() => inspect(item.id)}><span>{index + 1}</span></button>)}</div><div className="sequence-legend"><span><i className="allowed"/>Allowed</span><span><i className="rejected"/>Login rejected / route missing</span><span><i className="blocked"/>Blocked</span><span><i className="limited"/>Rate limited</span></div><p className="muted small">Each mark is an actual response in recorded order. Choose one to inspect the input and evidence. {scenarios[row.scenario].rule}</p></section>}
    <div className="inspection-grid"><section className="panel input-panel"><div className="panel-heading"><h3><Terminal size={17}/> {row ? 'Input received' : 'Example input'}</h3><span className="label neutral">{row ? row.method : 'Preview'}</span></div><pre className="payload-code">{row?.payload || chosen?.example || plan?.cases[0]?.payload || 'Choose a scenario to inspect its requests.'}</pre>{row?.matchedInputs?.length ? <details className="response-details"><summary>See input matched by the detector</summary><pre>{row.matchedInputs.join("\n")}</pre></details> : null}<p className="muted small">{row ? `Request ${rowIndex + 1} of ${rows.length} · ${row.path.split('?')[0]}` : 'An example from this scenario. Start an experiment to see actual request evidence.'}</p><div className="rule-box"><span className="eyebrow">What the detector checks</span><p>{info?.rule || 'Each scenario uses the relevant signature or behavior threshold. Normal controls should produce no alerts.'}</p></div></section><section className={`panel decision-panel ${decision?.tone || ''}`}><div className="panel-heading"><h3><ShieldCheck size={18}/> What happened</h3>{row && <span className={`label ${decision?.tone}`}>{decision?.label}</span>}</div><h3 className="decision-title">{decision?.label || 'Ready when you are.'}</h3><p>{decision?.detail || 'Start the experiment to see the actual response, the triggered rule, and the final outcome here.'}</p>{row && <><div className="evidence-lines"><div><span>HTTP response</span><strong>{row.status || 'No response'}</strong></div><div><span>Detector</span><strong>{row.detected.join(', ') || 'No alert recorded'}</strong></div><div><span>Saved alert IDs</span><strong>{row.alertIds.length ? [...new Set(row.alertIds)].map(id => `#${id}`).join(', ') : 'None'}</strong></div></div>{row.reasons?.length ? <div className="reason-box">{row.reasons.map(reason => <p key={reason}>{reason}</p>)}</div> : null}{row.decisions && <DecisionDetails evidence={row.decisions}/>} {row.retryAfter ? <p className="muted small">Server cooldown: retry after {row.retryAfter} seconds.</p> : null}<div className={`expectation-line ${row.passed ? '' : 'mismatch'}`}><span>{row.passed ? <Check size={16}/> : <X size={16}/>}</span><p><strong>{row.passed ? 'Matches expectation' : 'Differs from expectation'}</strong><br/>Expected HTTP {row.expectedStatus.join(' or ')}{row.expectedDetector ? ` + ${row.expectedDetector} alert` : row.benign ? ' + no security alert' : ''}.</p></div>{row.responseBody && <details className="response-details"><summary>View actual API response</summary><pre>{row.responseBody}</pre></details>}</>}</section></div>
    <div className="quiet-note"><ShieldCheck size={17}/><p>{info?.limit || 'This project measures rule-based detection on safe demo endpoints. A missed signature indicates a detection gap, not a proven successful exploit.'}</p></div>
    {run && <section className="panel"><div className="panel-heading"><div><p className="eyebrow">{running ? 'Results so far' : run.status === 'completed' ? 'Experiment complete' : `Experiment ${run.status}`}</p><h3>What the API actually did</h3></div><div className="inline-actions">{stats.alerts > 0 && <button className="btn compact" onClick={() => navigate('/activity/incidents/' + run.id)}>View incident <ArrowRight size={14}/></button>}{['html','csv','json'].map(value => <button key={value} className="btn compact" onClick={() => download(value)}><Download size={14}/>{value.toUpperCase()}</button>)}</div></div><div className="outcome-metrics"><div><strong>{stats.blocked}</strong><span>Blocked</span></div><div><strong>{stats.limited}</strong><span>Rate limited</span></div><div><strong>{stats.allowed}</strong><span>Allowed</span></div><div className={stats.gaps ? 'danger-text' : ''}><strong>{stats.gaps}</strong><span>Missing expected alerts</span></div><div><strong>{stats.alerts}</strong><span>Unique saved alerts</span></div></div><p className="muted small">{run.report?.passed || 0} of {run.progress} checked responses matched their expectations. {run.report?.failed || 0} differed. {run.report?.falsePositives || 0} normal requests produced a false alert or block. Login rejections, missing routes, and errors are separate from the allowed/blocked counts.</p>{run.error && <div className="error-box">{run.error}</div>}{run.report?.coverage && run.report.coverage.length > 1 && <div className="scenario-results">{run.report.coverage.map(item => <div key={item.scenario}><span>{scenarios[item.scenario]?.name}</span><strong className={item.failed ? 'danger-text' : ''}>{item.failed ? `${item.failed} differ` : `${item.passed} as expected`}</strong></div>)}</div>}</section>}
    {rows.length > 0 && <section className="panel request-log"><div className="panel-heading"><div><p className="eyebrow">Request timeline</p><h3>Choose a request to inspect it</h3></div>{running && <button className={`btn compact ${follow ? 'selected' : ''}`} onClick={() => { setFollow(true); setReplaying(false); }}> <Radio size={14}/>{follow ? 'Following live' : 'Follow live'}</button>}</div><div className="log-toolbar"><div className="filter-pills">{[['all','All requests'], ['blocked','Stopped'], ['allowed','Allowed'], ['gaps','Unexpected']].map(([value,label]) => <button key={value} className={filter === value ? 'selected' : ''} onClick={() => setFilter(value)}>{label}</button>)}</div><label className="search-field"><Search size={15}/><input aria-label="Search requests" value={search} placeholder="Search requests…" onChange={e => setSearch(e.target.value)}/></label></div><div className="timeline-scroll">{visibleRows.map((item, index) => { const actual = outcome(item); return <button key={item.id} className={`request-row ${row?.id === item.id ? 'selected' : ''}`} onClick={() => inspect(item.id)}><span className="request-index">{String(index + 1).padStart(2,'0')}</span><span className="request-row-main"><strong>{item.name}</strong><span>{item.method} {item.path.split('?')[0]} · {scenarios[item.scenario]?.name}</span></span><span className={`label ${actual.tone}`}>{actual.label}</span><code>{item.status || 'ERR'}</code><span className={item.passed ? 'check-note' : 'danger-text check-note'}>{item.passed ? <Check size={14}/> : <X size={14}/>}<span>{item.passed ? 'Expected' : 'Unexpected'}</span></span><ChevronRight size={16}/></button>; })}{!visibleRows.length && <div className="empty-panel small-empty">No requests match this filter.</div>}</div><p className="muted small log-footer"><ArrowDown size={13}/> Selecting a request updates the walkthrough above. Green “Expected” means the response matched the check, not that an attack succeeded.</p></section>}
    {catalog && <details className="source-details"><summary>Payload sources & experiment details</summary><p>Offline SecLists collection: {catalog.passwords} passwords, {catalog.sqlPayloads} SQL inputs, and {catalog.xssPayloads} XSS inputs. Standard uses curated examples; Extended adds up to 120 community probes.</p><p><a href={catalog.repository} target="_blank" rel="noreferrer">SecLists source</a> · pinned revision <code>{catalog.revision.slice(0,12)}</code>{run ? ` · run ${run.id}` : ''}</p></details>}
  </div>;
}
