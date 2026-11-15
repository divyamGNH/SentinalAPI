export function signAuditEntry(parent: string, id: string, payload: string) {
  return hmac(['sentinel.audit.entry.v1', parent, id, payload]);
}

function checkpointSignature(checkpoint: Omit<AuditCheckpoint, 'signature'>) {
  return hmac(['sentinel.audit.checkpoint.v1', checkpoint.legacy_through, checkpoint.head_id, checkpoint.head_tag, checkpoint.event_count]);
}

export function signCheckpoint(checkpoint: Omit<AuditCheckpoint, 'signature'>): AuditCheckpoint {
  return { ...checkpoint, signature: checkpointSignature(checkpoint) };
}
