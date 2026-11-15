import type { DecisionEvidence, ReviewVerdict } from '../../shared/defense';

export type Severity = 'low' | 'medium' | 'high';

export interface Alert {
  id: string | number;
  timestamp: string;
  detector_name: string;
  severity: Severity;
  source_ip: string;
  request_path: string;
  reason: string;
  matched_payload?: string;
  user_id: number;
  simulation_id?: string;
  simulation_case_id?: string;
  username?: string;
  status: 'open' | 'acknowledged' | 'resolved';
  acknowledged_at?: string | null;
  acknowledged_by?: number | null;
  resolved_at?: string | null;
  resolved_by?: number | null;
  decision_evidence?: DecisionEvidence | null;
  review_verdict?: ReviewVerdict;
  reviewed_at?: string | null;
  reviewed_by?: number | null;
}

export interface AuthEvent {
  id: number;
  user_id: number | null;
  username: string;
  user_name: string;
  event_type: 'login_success' | 'login_failure' | 'logout';
  source_ip: string;
  user_agent: string;
  created_at: string;
}
export interface AuditEvent {
  id: number;
  actor_user_id: number | null;
  username?: string;
  user_name?: string;
  action: string;
  entity_type: string;
  entity_id?: string;
  details: Record<string, unknown>;
  source_ip: string;
  created_at: string;
}
