import { randomUUID } from 'crypto';
import { performance } from 'perf_hooks';
import { setTimeout as delay } from 'timers/promises';
import { buildPlan, parseOptions, corpus } from '../attack-sim/catalog';
import { CaseResult, SimulationOptions, SimulationReport, SimulationCase } from '../shared/simulation';
import { createSimulation, getSimulationAlerts, PublicUser, recordAuditEvent, saveSimulation } from './db';
import { finishSimulation, registerSimulation } from './simulationContext';
import { requestEvidence } from '../shared/report';
import type { DecisionEvidence } from '../shared/defense';

export function simulationEnabled() { return process.env.ENABLE_SIMULATION !== 'false' && process.env.NODE_ENV !== 'production'; }

export async function startSimulation(user: PublicUser, token: string, input: Partial<SimulationOptions>, emit: () => void) {
  const options = parseOptions(input);
  const plan = buildPlan(options);
  const id = randomUUID();
  const controller = new AbortController();
  registerSimulation(id, user.id, plan.cases, controller);
  const config = { profile: options.profile, scenarios: options.scenarios, passwordLimit: options.passwordLimit, customWordlist: Boolean(options.passwords), presentation: options.presentation, customProbe: Boolean(options.probe) };
  let run;
  try {
    run = await createSimulation(id, user.id, plan.cases.length, config);
    await recordAuditEvent({ actorUserId: user.id, action: 'simulation_started', entityType: 'simulation', entityId: id, details: config });
  } catch (error) { finishSimulation(id); if (run) await saveSimulation(id, 0, null, 'failed', 'Unable to initialize run'); throw error; }
  void execute().catch(error => console.error('Unable to save simulation result:', error));
  return run;

  async function execute() {
    const started = performance.now();
    const results: CaseResult[] = [];
    const report = (): SimulationReport => ({
      cases: results, total: plan.cases.length, passed: results.filter(r => r.passed).length,
      failed: results.filter(r => !r.passed).length, errors: results.filter(r => r.error).length,
      falsePositives: results.filter(r => r.benign && (r.status === 403 || r.status === 429 || r.detected.length > 0)).length,
      missedDetections: results.filter(r => r.expectedDetector && !r.detected.includes(r.expectedDetector)).length,
      durationMs: Math.round(performance.now() - started), source: plan.source, passwordCount: plan.passwordCount,
      coverage: options.scenarios.map(scenario => ({ scenario, total: results.filter(r => r.scenario === scenario).length, passed: results.filter(r => r.scenario === scenario && r.passed).length, failed: results.filter(r => r.scenario === scenario && !r.passed).length }))
    });
    const base = `http://127.0.0.1:${process.env.PORT || 3000}`;
    async function send(item: SimulationCase): Promise<CaseResult> {
      const at = performance.now();
      try {
        const headers: Record<string,string> = { ...item.headers, Authorization: `Bearer ${token}`, 'x-sentinel-run': id, 'x-sentinel-case': item.id };
        let body: BodyInit | undefined;
        if (item.file) {
          const form = new FormData();
          form.append('file', new Blob([Uint8Array.from(item.file.bytes)], { type: item.file.type }), item.file.name);
          body = form;
        } else if (item.body) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(item.body); }
        const response = await fetch(base + item.path, { method: item.method, headers, body, redirect: 'error', signal: AbortSignal.any([controller.signal, AbortSignal.timeout(10_000)]) });
        const responseBody = (await response.text()).slice(0, 2000);
        const retryAfter = Number(response.headers.get('retry-after')) || undefined;
        const header = response.headers.get('x-sentinel-decisions');
        const decisions: DecisionEvidence[] | undefined = header ? JSON.parse(Buffer.from(header, 'base64url').toString()) : undefined;
        return { id: item.id, scenario: item.scenario, name: item.name, method: item.method, path: item.path, status: response.status, expectedStatus: item.expectedStatus, expectedDetector: item.expectedDetector, benign: Boolean(item.benign), latencyMs: Math.round(performance.now() - at), detected: [], alertIds: [], passed: false, responseBody, retryAfter, decisions };
      } catch (error) {
        return { id: item.id, scenario: item.scenario, name: item.name, method: item.method, path: item.path, status: 0, expectedStatus: item.expectedStatus, expectedDetector: item.expectedDetector, benign: Boolean(item.benign), latencyMs: Math.round(performance.now() - at), detected: [], alertIds: [], passed: false, error: error instanceof Error ? error.message : 'Request failed' };
      }
    }
    async function verify(batch: CaseResult[]) {
      const alerts = await getSimulationAlerts(id);
      for (const result of batch) {
        const matching = alerts.filter(a => a.simulation_case_id === result.id);
        const definition = plan.cases.find(item => item.id === result.id);
        if (definition) result.payload = requestEvidence(definition);
        // Flood requests race by design. Verify its cooldown probe against the
        // flood alert for the entire run, rather than assuming request ordering.
        if (result.scenario === 'flood' && result.name === 'Cooldown rejects subsequent request') {
          matching.push(...alerts.filter(a => a.detector_name === 'Request Flood / DDoS'));
          result.expectedDetector = 'Request Flood / DDoS';
        }
        result.detected = [...new Set(matching.map(a => a.detector_name))];
        result.alertIds = [...new Set(matching.map(a => a.id))];
        result.reasons = [...new Set(matching.map(a => a.reason))];
        result.matchedInputs = [...new Set(matching.map(a => a.matched_payload).filter(Boolean))];
        result.passed = !result.error && result.expectedStatus.includes(result.status) &&
          (!result.expectedDetector || result.detected.includes(result.expectedDetector)) && (!result.benign || matching.length === 0);
      }
      results.push(...batch);
      await saveSimulation(id, results.length, report());
      emit();
    }
    try {
      let index = 0;
      while (index < plan.cases.length && !controller.signal.aborted) {
        const item = plan.cases[index];
        if (item.delayMs) await delay(item.delayMs, undefined, { signal: controller.signal });
        if (item.concurrent) {
          const batch: SimulationCase[] = [];
          while (plan.cases[index]?.concurrent) batch.push(plan.cases[index++]);
          // Bounded worker pool; this is an application-layer lab load test.
          const pending: CaseResult[] = [];
          let cursor = 0;
          await Promise.all(Array.from({ length: 10 }, async () => {
            while (cursor < batch.length && !controller.signal.aborted) pending.push(await send(batch[cursor++]));
          }));
          await verify(pending);
        } else {
          await verify([await send(item)]); index++;
          // Pace individual requests for a live demonstration. Flood traffic stays
          // concurrent so its measured threshold and cooldown remain unchanged.
          if (options.presentation && index < plan.cases.length) await delay(700, undefined, { signal: controller.signal });
        }
      }
      const status = controller.signal.aborted ? 'cancelled' : 'completed';
      await saveSimulation(id, results.length, report(), status);
      await recordAuditEvent({ actorUserId: user.id, action: `simulation_${status}`, entityType: 'simulation', entityId: id, details: { passed: report().passed, failed: report().failed } });
    } catch (error) {
      const status = controller.signal.aborted ? 'cancelled' : 'failed';
      await saveSimulation(id, results.length, report(), status, status === 'cancelled' ? undefined : error instanceof Error ? error.message : 'Simulation failed');
      await recordAuditEvent({ actorUserId: user.id, action: `simulation_${status}`, entityType: 'simulation', entityId: id });
    } finally { finishSimulation(id); emit(); }
  }
}

export function simulationCatalog() {
  return { enabled: simulationEnabled(), revision: corpus.revision, repository: corpus.repository, passwords: corpus.passwords.length, sqlPayloads: corpus.sqli.length, xssPayloads: corpus.xss.length, thresholds: { bruteForce: '5 failures / 30 seconds', spraying: '5 usernames / 60 seconds', flood: '50 requests / 10 seconds; 30-second cooldown', enumeration: '15 missing routes / 20 seconds' } };
}
