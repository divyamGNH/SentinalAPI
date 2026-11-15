import { Express } from 'express';
import { getSimulation, listSimulations } from './db';
import { issueToken } from './auth';
import { simulationCatalog, simulationEnabled, startSimulation } from './simulation';
import { stopSimulation } from './simulationContext';
import { buildPlan, parseOptions } from '../attack-sim/catalog';
import { reportCsv, reportHtml } from '../shared/report';
import { requestEvidence } from '../shared/report';

const isUuid = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export function mountSimulations(app: Express) {
  app.get('/simulations/catalog', (_req, res) => res.json(simulationCatalog()));
  app.get('/simulations/plan', (req, res) => {
    try {
      const options = parseOptions({ profile: req.query.profile as 'standard' | 'extended' || 'standard', passwordLimit: Number(req.query.passwordLimit || 20), scenarios: typeof req.query.scenarios === 'string' ? req.query.scenarios.split(',') : undefined });
      const plan = buildPlan(options);
      // Expose labels and counts, never password bodies.
      res.json({ total: plan.cases.length, source: plan.source, passwordCount: plan.passwordCount, cases: plan.cases.map(item => ({ id: item.id, scenario: item.scenario, name: item.name, method: item.method, path: item.path, payload: requestEvidence(item), expectedStatus: item.expectedStatus, expectedDetector: item.expectedDetector, benign: item.benign })) });
    } catch (error) { res.status(400).json({ error: (error as Error).message }); }
  });
  app.get('/simulations', async (req, res) => {
    try { res.json(await listSimulations(req.authUser!)); } catch { res.status(500).json({ error: 'Unable to load simulations' }); }
  });
  app.post('/simulations', async (req, res) => {
    if (!simulationEnabled()) return res.status(403).json({ error: 'Local simulations are disabled' });
    if (req.authUser!.role === 'viewer') return res.status(403).json({ error: 'An analyst or administrator account is required' });
    try {
      const run = await startSimulation(req.authUser!, issueToken(req.authUser!), req.body || {}, () => app.emit('new-alert', req.authUser!.id));
      return res.status(202).json(run);
    } catch (error) {
      const message = (error as Error).message;
      return res.status(message.includes('already') ? 409 : 400).json({ error: message });
    }
  });
  app.get('/simulations/:id', async (req, res) => {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid run ID' });
    try {
      const run = await getSimulation(req.params.id, req.authUser!);
      if (!run) return res.status(404).json({ error: 'Simulation not found' });
      return res.json(run);
    } catch { return res.status(500).json({ error: 'Unable to load simulation' }); }
  });
  app.post('/simulations/:id/cancel', async (req, res) => {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid run ID' });
    try {
      const run = await getSimulation(req.params.id, req.authUser!);
      if (!run) return res.status(404).json({ error: 'Simulation not found' });
      stopSimulation(run.id);
      return res.json({ message: 'Cancellation requested' });
    } catch { return res.status(500).json({ error: 'Unable to cancel simulation' }); }
  });
  app.get('/simulations/:id/report', async (req, res) => {
    if (!isUuid(req.params.id)) return res.status(400).json({ error: 'Invalid run ID' });
    try {
      const run = await getSimulation(req.params.id, req.authUser!);
      if (!run) return res.status(404).json({ error: 'Simulation not found' });
      const format = req.query.format || 'json';
      if (!['json','csv','html'].includes(String(format))) return res.status(400).json({ error: 'Choose json, csv, or html' });
      res.setHeader('Content-Disposition', `attachment; filename="sentinel-${run.id}.${format}"`);
      if (format === 'csv') return res.type('text/csv').send(reportCsv(run));
      if (format === 'html') return res.type('text/html').send(reportHtml(run));
      return res.json(run);
    } catch { return res.status(500).json({ error: 'Unable to export report' }); }
  });
}
