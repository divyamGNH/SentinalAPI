import { Pool } from 'pg';
import type { PoolClient } from 'pg';
import type { DecisionEvidence, ReviewSummary, ReviewVerdict } from '../shared/defense';
import { initialCheckpoint, signAuditEntry, signCheckpoint, validCheckpoint, verifyAuditEntries } from './auditIntegrity';
import type { AuditCheckpoint, SignedAuditEntry } from './auditIntegrity';

const connectionString = process.env.DATABASE_URL || 'postgresql://localhost:5432/sentinelapi';

const pool = new Pool({ connectionString });

async function transaction<T>(work: (client: PoolClient) => Promise<T>, snapshot = false) {
  const client = await pool.connect();
  try {
    await client.query(snapshot ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN');
    const value = await work(client);
    await client.query('COMMIT');
    return value;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export interface AlertRecord {
  user_id: number;
  source_ip: string;
  detector_name: string;
  severity: string;
  matched_payload: string;
  request_path: string;
  reason: string;
  simulation_id?: string;
  simulation_case_id?: string;
  decision_evidence?: DecisionEvidence;
}

export interface Alert extends AlertRecord {
  id: number;
  timestamp: Date;
  status: AlertStatus;
  acknowledged_at: Date | null;
  acknowledged_by: number | null;
  resolved_at: Date | null;
  resolved_by: number | null;
  username?: string;
  review_verdict: ReviewVerdict;
  reviewed_at: Date | null;
  reviewed_by: number | null;
}

export type UserRole = 'admin' | 'analyst' | 'viewer';
export type AlertStatus = 'open' | 'acknowledged' | 'resolved';

export interface PublicUser {
  id: number;
  name: string;
  username: string;
  role: UserRole;
  active: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface UserRecord extends PublicUser {
  password_hash: string;
}

export async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'viewer')),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      source_ip TEXT NOT NULL,
      detector_name TEXT NOT NULL,
      severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
      matched_payload TEXT NOT NULL DEFAULT '',
      request_path TEXT NOT NULL,
      reason TEXT NOT NULL
    )
  `);

  await pool.query(`
    ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
  `);
  await pool.query("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open'");
  await pool.query('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ');
  await pool.query('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_by INTEGER REFERENCES users(id) ON DELETE SET NULL');
  await pool.query('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ');
  await pool.query('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolved_by INTEGER REFERENCES users(id) ON DELETE SET NULL');
  await pool.query('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS simulation_id UUID');
  await pool.query('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS simulation_case_id TEXT');
  await pool.query('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS decision_evidence JSONB');
  await pool.query(`ALTER TABLE alerts ADD COLUMN IF NOT EXISTS review_verdict TEXT NOT NULL DEFAULT 'needs_review'
    CHECK (review_verdict IN ('needs_review', 'confirmed', 'false_positive'))`);
  await pool.query('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ');
  await pool.query('ALTER TABLE alerts ADD COLUMN IF NOT EXISTS reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL');
  await pool.query(`CREATE TABLE IF NOT EXISTS simulation_runs (
    id UUID PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'running', created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ, progress INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL,
    config JSONB NOT NULL, report JSONB, error TEXT
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS alerts_simulation_idx ON alerts (simulation_id, simulation_case_id)');
  // A process restart interrupts in-memory workers; retain their partial report.
  await pool.query("UPDATE simulation_runs SET status = 'failed', completed_at = CURRENT_TIMESTAMP, error = 'API restarted before the run finished' WHERE status = 'running'");

  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_events (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      username TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK (event_type IN ('login_success', 'login_failure', 'logout')),
      source_ip TEXT NOT NULL,
      user_agent TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_events (
      id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      source_ip TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS alerts_timestamp_idx
    ON alerts (timestamp DESC)
  `);
  await pool.query('CREATE INDEX IF NOT EXISTS alerts_user_timestamp_idx ON alerts (user_id, timestamp DESC)');
  await pool.query('CREATE INDEX IF NOT EXISTS auth_events_user_created_idx ON auth_events (user_id, created_at DESC)');
  await pool.query('CREATE INDEX IF NOT EXISTS audit_events_created_idx ON audit_events (created_at DESC)');
  await pool.query('CREATE INDEX IF NOT EXISTS audit_events_entity_idx ON audit_events (entity_type, entity_id)');
  await initializeAuditIntegrity();
}

async function initializeAuditIntegrity() {
  await transaction(async client => {
    await client.query('LOCK TABLE audit_events IN ACCESS EXCLUSIVE MODE');
    await client.query('ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS integrity_tag TEXT');
    const existing = await client.query("SELECT to_regclass('audit_integrity_checkpoint') AS checkpoint");
    if (existing.rows[0].checkpoint) return;
    await client.query(`CREATE TABLE audit_integrity_checkpoint (
      singleton BOOLEAN PRIMARY KEY CHECK (singleton),
      legacy_through BIGINT NOT NULL,
      head_id BIGINT NOT NULL,
      head_tag TEXT NOT NULL,
      event_count INTEGER NOT NULL,
      signature TEXT NOT NULL
    )`);
    // A missing checkpoint table with existing signed rows is evidence loss.
    const state = await client.query('SELECT coalesce(max(id), 0)::text AS latest, count(integrity_tag)::int AS signed FROM audit_events');
    if (state.rows[0].signed) return;
    const initial = initialCheckpoint(state.rows[0].latest);
    await client.query(`INSERT INTO audit_integrity_checkpoint VALUES (true, $1, $1, '', 0, $2)`,
      [initial.legacy_through, initial.signature]);
  });
}

export async function assignUnownedAlertsToUser(userId: number) {
  await pool.query('UPDATE alerts SET user_id = $1 WHERE user_id IS NULL', [userId]);
}

export async function insertAlert(alert: AlertRecord) {
  // PostgreSQL TEXT cannot contain NUL; keep obfuscated payload evidence printable.
  const text = (value: string) => value.replace(/\u0000/g, '\\0');
  const result = await pool.query<Alert>(
    `INSERT INTO alerts
      (user_id, source_ip, detector_name, severity, matched_payload, request_path, reason, simulation_id, simulation_case_id, decision_evidence)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
     RETURNING *`,
    [
      alert.user_id,
      alert.source_ip,
      alert.detector_name,
      alert.severity,
      text(alert.matched_payload || ''),
      text(alert.request_path),
      text(alert.reason),
      alert.simulation_id || null,
      alert.simulation_case_id || null,
      alert.decision_evidence ?? null,
    ]
  );

  return result.rows[0];
}

export async function getAlerts(userId: number, options: { allUsers?: boolean; filterUserId?: number } = {}) {
  const values: number[] = [];
  const where: string[] = [];
  if (!options.allUsers) {
    values.push(userId);
    where.push(`a.user_id = $${values.length}`);
  } else if (options.filterUserId) {
    values.push(options.filterUserId);
    where.push(`a.user_id = $${values.length}`);
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const result = await pool.query<Alert>(
    `SELECT a.*, u.username FROM alerts a LEFT JOIN users u ON u.id = a.user_id
     ${clause} ORDER BY a.timestamp DESC LIMIT 250`,
    values
  );
  return result.rows;
}

export async function updateAlertStatus(alertId: number, status: AlertStatus, actor: PublicUser, sourceIp?: string) {
  return transaction(async client => {
    const ownership = actor.role === 'admin' ? '' : 'AND user_id = $3';
    const result = await client.query<Alert>(
    `UPDATE alerts SET
       status = $1,
       acknowledged_at = CASE WHEN $1 IN ('acknowledged', 'resolved') THEN COALESCE(acknowledged_at, CURRENT_TIMESTAMP) ELSE NULL END,
       acknowledged_by = CASE WHEN $1 IN ('acknowledged', 'resolved') THEN COALESCE(acknowledged_by, $3) ELSE NULL END,
       resolved_at = CASE WHEN $1 = 'resolved' THEN CURRENT_TIMESTAMP ELSE NULL END,
       resolved_by = CASE WHEN $1 = 'resolved' THEN $3 ELSE NULL END
     WHERE id = $2 ${ownership} RETURNING *`,
      [status, alertId, actor.id]
    );
    const alert = result.rows[0];
    if (!alert) return null;
    await appendAuditEvent(client, { actorUserId: actor.id, action: `alert_${status}`, entityType: 'alert', entityId: alert.id, details: { detector: alert.detector_name }, sourceIp });
    return alert;
  });
}

export async function reviewAlert(alertId: number, verdict: ReviewVerdict, actor: PublicUser, sourceIp?: string) {
  return transaction(async client => {
    const args = actor.role === 'admin' ? [alertId] : [alertId, actor.id];
    const result = await client.query<Alert>(
      `SELECT * FROM alerts WHERE id = $1 ${actor.role === 'admin' ? '' : 'AND user_id = $2'} FOR UPDATE`, args);
    const alert = result.rows[0];
    if (!alert || alert.review_verdict === verdict) return alert ?? null;
    const updated = await client.query<Alert>(
      `UPDATE alerts SET review_verdict = $2, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = $3
       WHERE id = $1 RETURNING *`, [alertId, verdict, actor.id]);
    await appendAuditEvent(client, {
      actorUserId: actor.id, action: 'alert_reviewed', entityType: 'alert', entityId: alertId, sourceIp,
      details: { detector: alert.detector_name, previous: alert.review_verdict, verdict },
    });
    return updated.rows[0];
  });
}

export async function getReviewSummary(user: PublicUser, allUsers: boolean, filterUserId?: number) {
  const owner = user.role === 'admin' && allUsers ? filterUserId : user.id;
  const result = await pool.query<ReviewSummary>(`
    SELECT detector_name AS detector, count(*)::int AS total,
      count(*) FILTER (WHERE review_verdict = 'confirmed')::int AS confirmed,
      count(*) FILTER (WHERE review_verdict = 'false_positive')::int AS "falsePositive",
      count(*) FILTER (WHERE review_verdict = 'needs_review')::int AS "needsReview"
    FROM alerts ${owner === undefined ? '' : 'WHERE user_id = $1'}
    GROUP BY detector_name ORDER BY "falsePositive" DESC, detector_name`, owner === undefined ? [] : [owner]);
  return result.rows;
}

const publicUserColumns = 'id, name, username, role, active, created_at, updated_at';

export async function findUserByUsername(username: string) {
  const result = await pool.query<UserRecord>('SELECT * FROM users WHERE username = $1', [username]);
  return result.rows[0] || null;
}

export async function findUserById(id: number): Promise<PublicUser | null>;
export async function findUserById(id: number, includePassword: true): Promise<UserRecord | null>;
export async function findUserById(id: number, includePassword = false) {
  const columns = includePassword ? '*' : publicUserColumns;
  const result = await pool.query(`SELECT ${columns} FROM users WHERE id = $1`, [id]);
  return result.rows[0] || null;
}

export async function createUser(input: { name: string; username: string; passwordHash: string; role: UserRole }) {
  const result = await pool.query<PublicUser>(
    `INSERT INTO users (name, username, password_hash, role)
     VALUES ($1, $2, $3, $4)
     RETURNING ${publicUserColumns}`,
    [input.name, input.username, input.passwordHash, input.role]
  );
  return result.rows[0];
}

export async function listUsers() {
  const result = await pool.query<PublicUser>(`SELECT ${publicUserColumns} FROM users ORDER BY created_at ASC`);
  return result.rows;
}

export async function updateUserPassword(userId: number, passwordHash: string) {
  await pool.query(
    'UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
    [passwordHash, userId]
  );
}

export async function recordAuthEvent(input: { userId: number | null; username: string; eventType: 'login_success' | 'login_failure' | 'logout'; sourceIp: string; userAgent: string }) {
  await pool.query(
    `INSERT INTO auth_events (user_id, username, event_type, source_ip, user_agent)
     VALUES ($1, $2, $3, $4, $5)`,
    [input.userId, input.username, input.eventType, input.sourceIp, input.userAgent]
  );
}

export async function listAuthEvents(user: PublicUser, allUsers = false) {
  const result = await pool.query(
    `SELECT e.*, COALESCE(u.name, e.username) AS user_name
     FROM auth_events e LEFT JOIN users u ON u.id = e.user_id
     ${allUsers && user.role === 'admin' ? '' : 'WHERE e.user_id = $1'}
     ORDER BY e.created_at DESC LIMIT 250`,
    allUsers && user.role === 'admin' ? [] : [user.id]
  );
  return result.rows;
}

type AuditInput = { actorUserId: number; action: string; entityType: string; entityId?: string | number; details?: Record<string, unknown>; sourceIp?: string };

// PostgreSQL builds the same JSON representation for signing and verification,
// preserving timestamps to microsecond precision without relying on session timezone.
const auditPayload = `jsonb_build_array(id::text, actor_user_id, action, entity_type, entity_id,
  details, source_ip, extract(epoch from created_at)::text)::text AS payload`;

async function appendAuditEvent(client: PoolClient, input: AuditInput) {
  const result = await client.query<AuditCheckpoint>('SELECT * FROM audit_integrity_checkpoint WHERE singleton FOR UPDATE');
  const checkpoint = result.rows[0];
  if (!checkpoint || !validCheckpoint(checkpoint)) throw new Error('Cannot append to an invalid audit checkpoint');
  const inserted = await client.query<SignedAuditEntry>(
    `INSERT INTO audit_events (actor_user_id, action, entity_type, entity_id, details, source_ip)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, ${auditPayload}`,
    [input.actorUserId, input.action, input.entityType, input.entityId == null ? null : String(input.entityId), JSON.stringify(input.details || {}), input.sourceIp || '']
  );
  const { id, payload } = inserted.rows[0];
  const tag = signAuditEntry(checkpoint.head_tag, id, payload);
  const updated = signCheckpoint({ legacy_through: checkpoint.legacy_through, head_id: id, head_tag: tag, event_count: checkpoint.event_count + 1 });
  await client.query('UPDATE audit_events SET integrity_tag = $2 WHERE id = $1', [id, tag]);
  await client.query(`UPDATE audit_integrity_checkpoint SET head_id = $1, head_tag = $2,
    event_count = $3, signature = $4 WHERE singleton`, [id, tag, updated.event_count, updated.signature]);
}

export async function recordAuditEvent(input: AuditInput) {
  await transaction(client => appendAuditEvent(client, input));
}

export async function verifyAuditTrail() {
  return transaction(async client => {
    const result = await client.query<AuditCheckpoint>('SELECT * FROM audit_integrity_checkpoint WHERE singleton');
    const checkpoint = result.rows[0];
    if (!checkpoint || !validCheckpoint(checkpoint)) return verifyAuditEntries(checkpoint, []);
    const entries = await client.query<SignedAuditEntry>(`SELECT id, integrity_tag, ${auditPayload}
      FROM audit_events WHERE id > $1 ORDER BY id`, [checkpoint.legacy_through]);
    return verifyAuditEntries(checkpoint, entries.rows);
  }, true);
}

export async function listAuditEvents(user: PublicUser, allUsers = false) {
  const result = await pool.query(
    `SELECT e.id, e.actor_user_id, e.action, e.entity_type, e.entity_id, e.details, e.source_ip,
       e.created_at, (e.integrity_tag IS NOT NULL) AS signed, u.username, u.name AS user_name
     FROM audit_events e LEFT JOIN users u ON u.id = e.actor_user_id
     ${allUsers && user.role === 'admin' ? '' : 'WHERE e.actor_user_id = $1'}
     ORDER BY e.created_at DESC LIMIT 250`,
    allUsers && user.role === 'admin' ? [] : [user.id]
  );
  return result.rows;
}

export async function closeDatabase() {
  await pool.end();
}

export async function createSimulation(id: string, userId: number, total: number, config: unknown) {
  return (await pool.query('INSERT INTO simulation_runs (id,user_id,total,config) VALUES ($1,$2,$3,$4) RETURNING *', [id,userId,total,JSON.stringify(config)])).rows[0];
}
export async function saveSimulation(id: string, progress: number, report: unknown, status = 'running', error?: string) {
  await pool.query(`UPDATE simulation_runs SET progress=$2, report=$3, status=$4, error=$5,
    completed_at=CASE WHEN $4='running' THEN NULL ELSE CURRENT_TIMESTAMP END WHERE id=$1`, [id,progress,JSON.stringify(report),status,error || null]);
}
export async function getSimulation(id: string, user: PublicUser, connection: Pool | PoolClient = pool) {
  return (await connection.query(`SELECT r.*, u.username FROM simulation_runs r JOIN users u ON u.id=r.user_id WHERE r.id=$1 ${user.role === 'admin' ? '' : 'AND r.user_id=$2'}`, user.role === 'admin' ? [id] : [id,user.id])).rows[0] || null;
}
export async function listSimulations(user: PublicUser) {
  return (await pool.query(`SELECT r.*, u.username FROM simulation_runs r JOIN users u ON u.id=r.user_id ${user.role === 'admin' ? '' : 'WHERE r.user_id=$1'} ORDER BY r.created_at DESC LIMIT 30`, user.role === 'admin' ? [] : [user.id])).rows;
}
export async function getSimulationAlerts(id: string, connection: Pool | PoolClient = pool) {
  return (await connection.query<Alert>('SELECT * FROM alerts WHERE simulation_id=$1 ORDER BY id', [id])).rows;
}

export async function listIncidents(user: PublicUser) {
  const admin = user.role === 'admin';
  const result = await pool.query(`
    SELECT r.id, r.created_at, r.status, r.config->'scenarios' AS scenarios, u.username,
      summary.alerts, summary.unresolved, summary.last_detection
    FROM simulation_runs r JOIN users u ON u.id = r.user_id
    JOIN LATERAL (
      SELECT count(*)::int AS alerts, count(*) FILTER (WHERE a.status <> 'resolved')::int AS unresolved,
        max(a.timestamp) AS last_detection
      FROM alerts a WHERE a.simulation_id = r.id
    ) summary ON summary.alerts > 0
    ${admin ? '' : 'WHERE r.user_id = $1'}
    ORDER BY summary.last_detection DESC LIMIT 30`, admin ? [] : [user.id]);
  return result.rows;
}

export async function getIncident(id: string, user: PublicUser) {
  return transaction(async client => {
    const run = await getSimulation(id, user, client);
    if (!run) return null;
    const alerts = await getSimulationAlerts(id, client);
    if (!alerts.length) return null;
    const events = await client.query(`
      SELECT e.id, e.action, e.details, e.created_at, e.entity_id, u.username
      FROM audit_events e LEFT JOIN users u ON u.id = e.actor_user_id
      WHERE (e.entity_type = 'simulation' AND e.entity_id = $1)
         OR (e.entity_type = 'alert' AND e.entity_id = ANY($2::text[]))
      ORDER BY e.created_at, e.id`, [id, alerts.map(alert => String(alert.id))]);
    return {
      id, username: run.username, status: run.status, scenarios: run.config.scenarios,
      created_at: run.created_at, completed_at: run.completed_at, progress: run.progress, total: run.total,
      alerts, events: events.rows,
    };
  }, true);
}
export async function databaseHealthy() { await pool.query('SELECT 1'); }
