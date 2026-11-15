import { useCallback, useEffect, useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import type { Alert, AuditEvent, AuthEvent, Severity } from './types';
import type { SimulationRun } from '../../shared/simulation';
import { SimulationLab } from './SimulationLab';
import { AlertReview, DecisionDetails, DefenseLab, IncidentTimeline, ReviewBreakdown } from './DefenseLab';
import { saveReview } from './defenseApi';
import type { ReviewVerdict } from '../../shared/defense';
import { scenarios, runStats } from './labModel';
import { Activity, ArrowRight, Check, CheckCircle2, ChevronRight, FileText, FlaskConical, GitCompare, History, KeyRound, LayoutDashboard, LogOut, Menu, RefreshCw, RotateCcw, Shield, UserRound, Users, X, Send } from 'lucide-react';
import { format } from 'date-fns';

const API = (import.meta.env.VITE_API_URL || 'http://localhost:3000').replace(/\/$/, '');
type User = { id: number; name: string; username: string; role: string; active: boolean };

function useHashRoute() {
  const [route, setRoute] = useState(location.hash.slice(1) || '/overview');
  useEffect(() => { const update = () => setRoute(location.hash.slice(1) || '/overview'); addEventListener('hashchange', update); return () => removeEventListener('hashchange', update); }, []);
  const navigate = (path: string) => { location.hash = path; };
  return { route, navigate };
}

function Login({ onLogin }: { onLogin: (token: string, user: User) => void }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('sentinel123');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setError(''); setBusy(true);
    try {
      const response = await fetch(`${API}/auth/login`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) });
      if (!response.ok) return setError('Invalid username or password.');
      const data = await response.json(); onLogin(data.token, data.user);
    } catch {
      setError('Cannot reach the SentinelAPI server.');
    } finally { setBusy(false); }
  };
  return <div className="login-page"><div className="login-visual"><div><Shield size={52}/><p className="eyebrow">SentinelAPI</p><h1>See threats.<br/>Understand attacks.<br/>Respond faster.</h1><p>A local lab for exploring API attacks, understanding detection, and inspecting real evidence.</p></div></div><form className="login-card" onSubmit={submit}><div className="login-mark"><Shield size={30}/></div><p className="eyebrow">Secure console</p><h2>Welcome back</h2><p className="muted">Sign in to explore your local security playground.</p><label>Username<input autoComplete="username" required value={username} onChange={e => setUsername(e.target.value)}/></label><label>Password<input autoComplete="current-password" type="password" required value={password} onChange={e => setPassword(e.target.value)}/></label>{error && <div className="error-box">{error}</div>}<button className="primary-btn" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'} <ChevronRight size={18}/></button><div className="demo-credentials"><strong>Demo access</strong><span>admin / sentinel123</span></div></form></div>;
}

function UserManagement({ token }: { token: string }) {
  const [users, setUsers] = useState<User[]>([]);
  const [form, setForm] = useState({ name: '', username: '', password: '', role: 'analyst' });
  const [message, setMessage] = useState('');
  const load = useCallback(async () => { const response = await fetch(`${API}/auth/users`, { headers: { Authorization: `Bearer ${token}` } }); if (response.ok) setUsers(await response.json()); }, [token]);
  useEffect(() => { load(); }, [load]);
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setMessage('');
    try {
      const response = await fetch(`${API}/auth/users`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(form) });
      const data = await response.json();
      if (!response.ok) return setMessage(data.error || 'Unable to create user.');
      setForm({ name: '', username: '', password: '', role: 'analyst' }); setMessage('User created successfully.'); await load();
    } catch { setMessage('Unable to reach the API. Check that the backend is running.'); }
  };
  return <><div className="page-intro"><p>Create separate accounts so every analyst sees only alerts generated under their own identity.</p></div><div className="admin-grid"><form className="settings-card" onSubmit={submit}><p className="eyebrow">Administrator</p><h3>Create user</h3><label>Full name<input required value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}/></label><label>Username<input required value={form.username} onChange={e => setForm({ ...form, username: e.target.value })}/></label><label>Temporary password<input required type="password" minLength={10} value={form.password} onChange={e => setForm({ ...form, password: e.target.value })}/></label><label>Role<select value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}><option value="analyst">Analyst</option><option value="viewer">Viewer</option><option value="admin">Administrator</option></select></label>{message && <div className="form-message">{message}</div>}<button className="primary-btn">Create account</button></form><div className="settings-card user-list"><p className="eyebrow">Directory</p><h3>Users</h3>{users.map(item => <div className="user-row" key={item.id}><UserRound/><div><strong>{item.name}</strong><span>@{item.username}</span></div><span className="role-chip">{item.role}</span></div>)}</div></div></>;
}

function AccountSecurity({ token }: { token: string }) {
  const [currentPassword, setCurrentPassword] = useState(''); const [newPassword, setNewPassword] = useState(''); const [message, setMessage] = useState('');
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setMessage('');
    try {
      const response = await fetch(`${API}/auth/change-password`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ currentPassword, newPassword }) });
      if (!response.ok) { const data = await response.json(); return setMessage(data.error || 'Unable to change password.'); }
      setCurrentPassword(''); setNewPassword(''); setMessage('Password changed successfully.');
    } catch { setMessage('Unable to reach the API. Check that the backend is running.'); }
  };
  return <><div className="page-intro"><p>Update the password for your signed-in account.</p></div><form className="settings-card narrow" onSubmit={submit}><p className="eyebrow">Account security</p><h3>Change password</h3><label>Current password<input required type="password" value={currentPassword} onChange={e => setCurrentPassword(e.target.value)}/></label><label>New password<input required type="password" minLength={10} value={newPassword} onChange={e => setNewPassword(e.target.value)}/></label><p className="muted small">Use at least 10 characters containing letters and numbers.</p>{message && <div className="form-message">{message}</div>}<button className="primary-btn">Update password</button></form></>;
}

function EventLog({ token, user, kind }: { token: string; user: User; kind: 'login' | 'audit' }) {
  const [events, setEvents] = useState<Array<AuthEvent | AuditEvent>>([]);
  const [allUsers, setAllUsers] = useState(user.role === 'admin');
  const [error, setError] = useState('');
  const load = useCallback(async () => {
    const path = kind === 'login' ? '/auth/events' : '/audit-events';
    const scope = allUsers && user.role === 'admin' ? '?scope=all' : '';
    try {
      const response = await fetch(`${API}${path}${scope}`, { headers: { Authorization: `Bearer ${token}` } });
      if (!response.ok) throw new Error('Request failed');
      setEvents(await response.json()); setError('');
    } catch { setError('Unable to load events. Check the API connection or sign in again.'); }
  }, [allUsers, kind, token, user.role]);
  useEffect(() => { load(); }, [load]);
  return <>{error && <div className="error-box" role="alert">{error}</div>}<div className="page-intro"><p>{kind === 'login' ? 'Successful logins, failed attempts, and logouts.' : 'Security-relevant administrative and investigation actions.'}</p><div className="inline-actions">{user.role === 'admin' && <select className="select-input" value={allUsers ? 'all' : 'mine'} onChange={e => setAllUsers(e.target.value === 'all')}><option value="all">All users</option><option value="mine">My activity</option></select>}<button className="btn" onClick={load}><RefreshCw size={16}/>Refresh</button></div></div><div className="glass-panel table-wrapper"><table className="alerts-table"><thead><tr><th>Time</th><th>User</th><th>Event</th><th>Entity</th><th>Source IP</th><th>Details</th></tr></thead><tbody>{events.length ? events.map(event => { const loginEvent = event as AuthEvent; const auditEvent = event as AuditEvent; return <tr key={event.id}><td className="muted">{format(new Date(event.created_at), 'MMM d, HH:mm:ss')}</td><td><strong>{event.user_name || event.username || 'Unknown'}</strong>{event.username && <div className="muted small">@{event.username}</div>}</td><td><span className={`status-badge ${loginEvent.event_type === 'login_failure' ? 'open' : 'acknowledged'}`}>{loginEvent.event_type || auditEvent.action}</span></td><td>{auditEvent.entity_type ? `${auditEvent.entity_type}${auditEvent.entity_id ? ` #${auditEvent.entity_id}` : ''}` : 'Authentication'}</td><td><span className="code-block">{event.source_ip}</span></td><td className="muted">{auditEvent.details ? JSON.stringify(auditEvent.details) : loginEvent.user_agent || '—'}</td></tr>; }) : <tr><td colSpan={6}><div className="empty-state"><History size={42}/><h3>No events recorded yet.</h3></div></td></tr>}</tbody></table></div></>;
}


function Overview({ token, navigate }: { token: string; navigate: (path: string) => void }) {
  const [runs, setRuns] = useState<SimulationRun[]>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true;
    fetch(API + '/simulations', { headers: { Authorization: 'Bearer ' + token } }).then(async response => {
      if (!response.ok) throw new Error('Unable to load experiment history.');
      const data = await response.json(); if (active) setRuns(data);
    }).catch(err => { if (active) setError(err.message); });
    return () => { active = false; };
  }, [token]);
  const rows = runs.flatMap(run => run.report?.cases || []);
  const stats = runStats(rows);
  return <div className="screen-stack">
    <section className="overview-hero"><div><span className="environment-tag"><span/>Your local security lab</span><h2>See the attack.<br/><em>Understand the defense.</em></h2><p>Explore how a security layer inspects API requests, spots suspicious input, and decides what reaches the application.</p><div className="inline-actions"><button className="btn primary" onClick={() => navigate('/simulations')}>Open playground <ArrowRight size={17}/></button><button className="btn" onClick={() => navigate('/reports')}>View saved results <FileText size={16}/></button></div></div><div className="hero-system" aria-label="Request flows through Sentinel security into the demo API"><div className="system-node"><Send size={22}/><span>Incoming request</span><code>POST /search</code></div><span className="system-connector"/><div className="system-node sentinel-node"><Shield size={26}/><span>Sentinel inspection</span><small>Signatures + behavior rules</small></div><div className="system-branches"><span className="branch-block">Suspicious → block</span><span className="branch-allow">Normal → demo API</span></div></div></section>
    {error && <div className="error-box" role="alert">{error}</div>}
    <section className="overview-metrics"><div><span>Saved experiments</span><strong>{runs.length}</strong><small>Latest available runs</small></div><div><span>Requests inspected</span><strong>{rows.length}</strong><small>Across these experiments</small></div><div><span>Blocked or rate limited</span><strong>{stats.blocked + stats.limited}</strong><small>Actual HTTP 403 / 429</small></div><div><span>Missing expected alerts</span><strong className={stats.gaps ? 'danger-text' : ''}>{stats.gaps}</strong><small>Inputs to investigate</small></div></section>
    <div className="section-heading"><div><p className="eyebrow">Start with a question</p><h3>What would you like to demonstrate?</h3></div><button className="text-btn" onClick={() => navigate('/simulations')}>All 12 scenarios <ArrowRight size={15}/></button></div>
    <div className="starter-grid">{[['sqli','Can suspicious input be stopped?','Send SQL-like input and follow the request through the security layer.'],['brute','When does guessing become an attack?','Watch failed login attempts build up until the threshold triggers.'],['flood','Can the API recover after a flood?','Observe a burst, a temporary cooldown, and normal access returning.']].map(([key,title,text]) => <button className="starter-card" key={key} onClick={() => navigate('/simulations/' + key)}><span className="card-category">{scenarios[key].name}</span><h3>{title}</h3><p>{text}</p><span className="card-action">Try it <ArrowRight size={15}/></span></button>)}</div>
    <section className="panel project-strip"><div><p className="eyebrow">The project, simply</p><h3>A rule-based API security lab.</h3><p>We generate controlled traffic, inspect each request, save security alerts, and compare actual behavior with the expected response. No machine learning is used.</p></div><div><strong>11 detectors. Real HTTP. Saved evidence.</strong><p>The demo endpoints keep attack payloads inert. Detection gaps are visible in results, so you can discuss both what works and what needs improvement.</p></div></section>
    <div className="section-heading"><div><p className="eyebrow">Continue exploring</p><h3>Recent experiments</h3></div><button className="text-btn" onClick={() => navigate('/reports')}>All results <ArrowRight size={15}/></button></div>
    <div className="recent-runs">{runs.slice(0,4).map(run => <button key={run.id} onClick={() => navigate('/reports/' + run.id)}><span className="icon-tile"><FileText size={19}/></span><div><strong>{run.config.scenarios.length === 1 ? scenarios[run.config.scenarios[0]]?.name : run.config.scenarios.length + ' scenarios'}</strong><span>{new Date(run.created_at).toLocaleString()} · {run.progress}/{run.total} requests</span></div><span className={'label ' + (run.status === 'completed' ? 'success' : 'warning')}>{run.status}</span><ChevronRight size={17}/></button>)}{!runs.length && <div className="empty-panel"><FlaskConical size={28}/><p>No experiments yet. Start with SQL injection or normal traffic.</p><button className="btn" onClick={() => navigate('/simulations/sqli')}>Run your first scenario <ArrowRight size={15}/></button></div>}</div>
  </div>;
}

function DetectionFeed({ alerts, showUser, onStatusChange, onReview, navigate }: { alerts: Alert[]; showUser: boolean; onStatusChange?: (alert: Alert, status: Alert['status']) => void; onReview: (alert: Alert, verdict: ReviewVerdict) => Promise<void>; navigate: (path: string) => void }) {
  return <div className="detection-feed">{alerts.map(alert => <article className="detection-card" key={alert.id}><div className="split"><div className="detection-title"><span className="scenario-icon"><Shield size={18}/></span><div><h3>{alert.detector_name === 'Credential Stuffing' ? 'Password spraying' : alert.detector_name}</h3><p>{format(new Date(alert.timestamp), 'MMM d, HH:mm:ss')} · #{alert.id}{showUser ? ' · @' + (alert.username || alert.user_id) : ''}</p></div></div><span className={'status-badge ' + alert.status}>{alert.status}</span></div><p className="detection-reason">{alert.reason}</p><div className="detection-meta"><code>{alert.request_path}</code><span>{alert.source_ip}</span><span className={'label ' + (alert.severity === 'high' ? 'danger' : 'warning')}>{alert.severity}</span></div><details className="response-details"><summary>Inspect matched input</summary><pre>{alert.matched_payload || 'Behavior threshold triggered; no single payload.'}</pre></details>{alert.decision_evidence && <DecisionDetails evidence={[alert.decision_evidence]}/>}<AlertReview alert={alert} canReview={Boolean(onStatusChange)} onReview={onReview}/><div className="detection-actions">{alert.simulation_id && <button className="text-btn" onClick={() => navigate('/activity/incidents/' + alert.simulation_id)}>Open incident <ArrowRight size={14}/></button>}<div className="inline-actions">{onStatusChange && <>{alert.status === 'open' && <button className="btn compact" onClick={() => onStatusChange(alert, 'acknowledged')}><Check size={14}/>Acknowledge</button>}{alert.status !== 'resolved' && <button className="btn compact" onClick={() => onStatusChange(alert, 'resolved')}><CheckCircle2 size={14}/>Resolve</button>}{alert.status !== 'open' && <button className="btn compact" onClick={() => onStatusChange(alert, 'open')}><RotateCcw size={14}/>Reopen</button>}</>}</div></div></article>)}{!alerts.length && <div className="empty-panel"><Shield size={28}/><h3>No matching detections.</h3><p>Run a scenario to generate real detector evidence.</p></div>}</div>;
}

function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem('sentinel-token') || '');
  const [user, setUser] = useState<User | null>(() => { try { return JSON.parse(sessionStorage.getItem('sentinel-user') || 'null'); } catch { return null; } });
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);
  const [filter, setFilter] = useState<Severity | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<Alert['status'] | 'all'>('all');
  const [reviewRefresh, setReviewRefresh] = useState(0);
  const [alertScope, setAlertScope] = useState<'mine' | 'all'>('mine');
  const [selectedUserId, setSelectedUserId] = useState('all');
  const [users, setUsers] = useState<User[]>([]);
  const [menuOpen, setMenuOpen] = useState(false);
  const [error, setError] = useState('');
  const { route, navigate } = useHashRoute();
  const go = (path: string) => { navigate(path); setMenuOpen(false); };
  const fetchAlerts = useCallback(async () => {
    if (!token) return;
    const params = new URLSearchParams();
    if (user?.role === 'admin' && alertScope === 'all') {
      params.set('scope', 'all'); if (selectedUserId !== 'all') params.set('userId', selectedUserId);
    }
    try {
      const response = await fetch(API + '/alerts' + (params.size ? '?' + params : ''), { headers: { Authorization: 'Bearer ' + token } });
      if (response.status === 401) { sessionStorage.removeItem('sentinel-token'); sessionStorage.removeItem('sentinel-user'); setToken(''); setUser(null); return; }
      if (!response.ok) throw new Error('Unable to load activity.');
      setAlerts(await response.json()); setError('');
    } catch { setError('Unable to load activity. Confirm that the API is running.'); }
  }, [alertScope, selectedUserId, token, user?.role]);
  useEffect(() => {
    void fetchAlerts(); if (!token) return;
    const scope = user?.role === 'admin' && alertScope === 'all' ? '?scope=all' : '';
    const source = new EventSource(API + '/alerts/stream' + scope, { withCredentials: true });
    source.onopen = () => setConnected(true); source.onerror = () => setConnected(false); source.onmessage = () => { void fetchAlerts(); };
    return () => { source.close(); setConnected(false); };
  }, [alertScope, fetchAlerts, token, user?.role]);
  useEffect(() => {
    if (token && user?.role === 'admin') fetch(API + '/auth/users', { headers: { Authorization: 'Bearer ' + token } }).then(response => response.ok ? response.json() : []).then(setUsers).catch(() => setError('Unable to load the user directory.'));
  }, [token, user?.role, route]);
  const login = (newToken: string, newUser: User) => { sessionStorage.setItem('sentinel-token', newToken); sessionStorage.setItem('sentinel-user', JSON.stringify(newUser)); setToken(newToken); setUser(newUser); navigate('/overview'); };
  const logout = () => {
    if (token) void fetch(API + '/auth/logout', { method: 'POST', credentials: 'include', headers: { Authorization: 'Bearer ' + token } }).catch(() => undefined);
    sessionStorage.removeItem('sentinel-token'); sessionStorage.removeItem('sentinel-user'); setToken(''); setUser(null); setAlerts([]); setAlertScope('mine'); setSelectedUserId('all'); setConnected(false); setError('');
  };
  const updateStatus = async (alert: Alert, status: Alert['status']) => {
    try {
      const response = await fetch(API + '/alerts/' + alert.id + '/status', { method: 'PATCH', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify({ status }) });
      if (!response.ok) throw new Error('Unable to update alert'); await fetchAlerts();
    } catch { setError('Unable to save the alert status. Please retry.'); }
  };
  const updateReview = async (alert: Alert, verdict: ReviewVerdict) => {
    const updated = await saveReview({ api: API, token }, alert.id, verdict);
    setAlerts(current => current.map(item => item.id === updated.id ? { ...item, ...updated } : item));
    setReviewRefresh(value => value + 1);
  };
  const visibleAlerts = useMemo(() => alerts.filter(a => (filter === 'all' || a.severity === filter) && (statusFilter === 'all' || (a.status || 'open') === statusFilter)), [alerts, filter, statusFilter]);
  if (!token || !user) return <Login onLogin={login}/>;
  const path = route.split('/');
  const legacyScenario: Record<string, string> = { 'sql-injection': 'sqli', xss: 'xss', 'path-traversal': 'traversal', 'command-injection': 'command', 'brute-force': 'brute', 'credential-stuffing': 'spraying', ddos: 'flood', ssrf: 'ssrf', 'file-upload': 'upload', scanner: 'scanner', enumeration: 'enumeration' };
  const isLab = path[1] === 'simulations' || path[1] === 'attacks';
  const isResults = path[1] === 'reports';
  const isDefense = path[1] === 'defense';
  const isActivity = ['activity','alerts','login-history','audit-log'].includes(path[1]);
  const tab = route === '/login-history' || path[2] === 'logins' ? 'logins' : route === '/audit-log' || path[2] === 'audit' ? 'audit' : path[2] === 'incidents' ? 'incidents' : 'detections';
  const title = isLab ? 'Attack playground' : isResults ? 'Results' : isDefense ? 'Defense lab' : isActivity ? 'Activity' : route === '/users' ? 'Team' : route === '/account' ? 'Account' : 'Overview';
  const renderContent = () => {
    if (isLab || isResults) return <SimulationLab token={token} role={user.role} userId={user.id} api={API} scenario={isLab ? (path[1] === 'attacks' ? legacyScenario[path[2]] : path[2]) : undefined} results={isResults} runId={isResults ? path[2] : undefined} navigate={go}/>;
    if (isDefense) return <DefenseLab api={API} token={token} admin={user.role === 'admin'} tab={path[2]} navigate={go}/>;
    if (isActivity) return <div className="screen-stack"><div className="page-heading"><div><p className="eyebrow">Operational evidence</p><h2>What the system recorded.</h2><p>Investigate detections and review account activity in one place.</p></div></div><div className="tabs">{[['detections','Detections'],['incidents','Incidents'],['logins','Sign-in history'],['audit','Audit trail']].map(([key,label]) => <button key={key} className={tab === key ? 'selected' : ''} onClick={() => go('/activity/' + key)}>{label}</button>)}</div>{tab === 'incidents' ? <IncidentTimeline api={API} token={token} id={path[3]} canReview={user.role !== 'viewer'} navigate={go}/> : tab === 'logins' ? <EventLog token={token} user={user} kind="login"/> : tab === 'audit' ? <EventLog token={token} user={user} kind="audit"/> : <><div className="activity-toolbar"><div className="inline-actions">{user.role === 'admin' && <><select aria-label="Detection scope" value={alertScope} onChange={e => { setAlertScope(e.target.value as 'mine' | 'all'); setSelectedUserId('all'); }}><option value="mine">My detections</option><option value="all">All users</option></select>{alertScope === 'all' && <select aria-label="Filter by user" value={selectedUserId} onChange={e => setSelectedUserId(e.target.value)}><option value="all">Every user</option>{users.map(item => <option key={item.id} value={item.id}>@{item.username}</option>)}</select>}</>}<select aria-label="Severity filter" value={filter} onChange={e => setFilter(e.target.value as Severity | 'all')}><option value="all">All severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><select aria-label="Status filter" value={statusFilter} onChange={e => setStatusFilter(e.target.value as Alert['status'] | 'all')}><option value="all">All statuses</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="resolved">Resolved</option></select></div><button className="btn" onClick={fetchAlerts}><RefreshCw size={15}/>Refresh</button></div><p className="muted small">{visibleAlerts.length} matching records from the latest loaded detections.</p><ReviewBreakdown api={API} token={token} scope={alertScope} userId={selectedUserId} refresh={reviewRefresh}/><DetectionFeed onReview={updateReview} alerts={visibleAlerts} showUser={alertScope === 'all'} onStatusChange={user.role === 'viewer' ? undefined : updateStatus} navigate={go}/></>}</div>;
    if (route === '/users' && user.role === 'admin') return <UserManagement token={token}/>;
    if (route === '/account') return <AccountSecurity token={token}/>;
    return <Overview token={token} navigate={go}/>;
  };
  return <div className="app-shell"><aside className={menuOpen ? 'sidebar open' : 'sidebar'}><div className="sidebar-brand"><span className="brand-shield"><Shield size={23}/></span><span>sentinel<span className="brand-light">api</span><small>SECURITY PLAYGROUND</small></span><button aria-label="Close navigation" className="close-menu" onClick={() => setMenuOpen(false)}><X/></button></div><span className="nav-caption">WORKSPACE</span><nav><button className={title === 'Overview' ? 'active' : ''} onClick={() => go('/overview')}><LayoutDashboard/>Overview</button><button className={isLab ? 'active' : ''} onClick={() => go('/simulations')}><FlaskConical/>Attack playground</button><button className={isResults ? 'active' : ''} onClick={() => go('/reports')}><FileText/>Results</button><button className={isDefense ? 'active' : ''} onClick={() => go('/defense')}><GitCompare/>Defense lab</button><button className={isActivity ? 'active' : ''} onClick={() => go('/activity/detections')}><Activity/>Activity</button></nav><div className="sidebar-bottom"><div className="sidebar-note"><span className="environment-tag"><span/>Local demo</span><p>Explore attacks.<br/>Understand the response.</p></div><span className="nav-caption">MANAGE</span><nav>{user.role === 'admin' && <button className={route === '/users' ? 'active' : ''} onClick={() => go('/users')}><Users/>Team</button>}<button className={route === '/account' ? 'active' : ''} onClick={() => go('/account')}><KeyRound/>Account</button></nav><div className="sidebar-user"><span className="avatar">{user.name.charAt(0).toUpperCase()}</span><div><strong>{user.name}</strong><span>{user.role}</span></div><button aria-label="Sign out" title="Sign out" onClick={logout}><LogOut size={17}/></button></div></div></aside>{menuOpen && <button aria-label="Close navigation overlay" className="menu-overlay" onClick={() => setMenuOpen(false)}/>}<main className="workspace"><header className="workspace-header"><button aria-label="Open navigation" className="menu-btn" onClick={() => setMenuOpen(true)}><Menu/></button><div className="header-crumb">Workspace <ChevronRight size={14}/><h1>{title}</h1></div><div className="live-pill" title="Connection to the live activity stream"><i className={connected ? 'online' : ''}/>{connected ? 'Live updates connected' : 'Live updates offline'}</div></header><div className="page-content">{error && <div className="error-box" role="alert">{error}</div>}{renderContent()}</div><footer className="workspace-footer"><span>SentinelAPI · A rule-based security demonstration</span><span>Local traffic. Real evidence.</span></footer></main></div>;
}
export default App;
