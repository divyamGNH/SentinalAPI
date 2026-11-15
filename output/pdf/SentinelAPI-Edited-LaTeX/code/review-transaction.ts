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
