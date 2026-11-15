import type { Express } from 'express';
import { reviewVerdicts } from '../shared/defense';
import type { ReviewVerdict } from '../shared/defense';
import { requireAdmin } from './auth';
import { demonstrateAuditIntegrity } from './auditIntegrity';
import { getIncident, getReviewSummary, listIncidents, reviewAlert, verifyAuditTrail } from './db';
import { compareSqlRules } from './ruleComparison';

export function mountDefenseRoutes(app: Express) {
  app.get('/defense/comparison', (_req, res) => res.json(compareSqlRules()));

  app.get('/defense/incidents', async (req, res) => {
    try {
      return res.json(await listIncidents(req.authUser!));
    } catch (error) {
      console.error('Incident list failed:', error);
      return res.status(500).json({ error: 'Unable to load incidents.' });
    }
  });

  app.get('/defense/incidents/:id', async (req, res) => {
    if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(req.params.id)) {
      return res.status(400).json({ error: 'Invalid experiment ID.' });
    }
    try {
      const incident = await getIncident(req.params.id, req.authUser!);
      if (!incident) return res.status(404).json({ error: 'Incident not found.' });
      return res.json(incident);
    } catch (error) {
      console.error('Incident lookup failed:', error);
      return res.status(500).json({ error: 'Unable to load the incident.' });
    }
  });

  app.get('/defense/reviews', async (req, res) => {
    const all = req.query.scope === 'all';
    if (all && req.authUser!.role !== 'admin') return res.status(403).json({ error: 'Administrator access required.' });
    const userId = req.query.userId === undefined ? undefined : Number(req.query.userId);
    if (userId !== undefined && (!all || !Number.isSafeInteger(userId) || userId <= 0 || userId > 2_147_483_647)) {
      return res.status(400).json({ error: 'Choose an account within the all-users scope.' });
    }
    try {
      return res.json(await getReviewSummary(req.authUser!, all, userId));
    } catch (error) {
      console.error('Alert review summary failed:', error);
      return res.status(500).json({ error: 'Unable to load review totals.' });
    }
  });

  app.patch('/defense/alerts/:id/review', async (req, res) => {
    const actor = req.authUser!;
    if (actor.role === 'viewer') return res.status(403).json({ error: 'Only analysts and administrators can review alerts.' });
    const id = Number(req.params.id);
    const verdict = req.body?.verdict as ReviewVerdict;
    if (!Number.isSafeInteger(id) || id <= 0 || id > 2_147_483_647 || !reviewVerdicts.includes(verdict)) {
      return res.status(400).json({ error: 'Choose a valid alert and review verdict.' });
    }
    try {
      const alert = await reviewAlert(id, verdict, actor, req.ip);
      if (!alert) return res.status(404).json({ error: 'Alert not found.' });
      app.emit('new-alert', alert.user_id);
      return res.json(alert);
    } catch (error) {
      console.error('Alert review failed:', error);
      return res.status(500).json({ error: 'Unable to save the review.' });
    }
  });

  app.get('/defense/audit/verify', requireAdmin, async (_req, res) => {
    try {
      return res.json(await verifyAuditTrail());
    } catch (error) {
      console.error('Audit verification failed:', error);
      return res.status(500).json({ error: 'Unable to verify the audit trail.' });
    }
  });

  app.post('/defense/audit/demo', requireAdmin, (req, res) => {
    const change = req.body?.change;
    if (change !== 'edit' && change !== 'delete') return res.status(400).json({ error: 'Choose an edit or deletion.' });
    return res.json(demonstrateAuditIntegrity(change));
  });
}
