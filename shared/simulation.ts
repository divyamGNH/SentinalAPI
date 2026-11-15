import type { DecisionEvidence } from './defense';

export const scenarioNames: Record<string, string> = {
  benign: 'Normal Traffic', sqli: 'SQL Injection', xss: 'XSS', traversal: 'Path Traversal',
  command: 'Command Injection', brute: 'Brute-Force Login', spraying: 'Password Spraying',
  ssrf: 'SSRF Attempt', upload: 'Malicious File Upload', scanner: 'Scanner / Attack Tool',
  enumeration: 'Endpoint Enumeration', flood: 'Local Request Flood'
};
export interface SimulationOptions {
  profile: 'standard' | 'extended';
  scenarios: string[];
  passwordLimit: number;
  passwords?: string[];
  presentation?: boolean;
  probe?: { value: string; expect: 'block' | 'allow' };
}
export interface SimulationCase {
  id: string; scenario: string; lane: string; name: string;
  method: string; path: string; body?: unknown; headers?: Record<string, string>;
  file?: { name: string; bytes: number[]; type: string };
  expectedStatus: number[]; expectedDetector?: string; benign?: boolean;
  concurrent?: boolean;
  delayMs?: number;
}
export interface CaseResult {
  id: string; scenario: string; name: string; method: string; path: string;
  expectedStatus: number[]; status: number; expectedDetector?: string;
  detected: string[]; alertIds: number[]; latencyMs: number;
  passed: boolean; benign: boolean; error?: string;
  payload?: string;
  reasons?: string[];
  matchedInputs?: string[];
  responseBody?: string;
  retryAfter?: number;
  decisions?: DecisionEvidence[];
}
export interface SimulationReport {
  cases: CaseResult[];
  total: number; passed: number; failed: number; errors: number;
  falsePositives: number; missedDetections: number; durationMs: number;
  source: string; passwordCount: number;
  coverage: Array<{ scenario: string; total: number; passed: number; failed: number }>;
}
export interface SimulationRun {
  id: string; user_id: number; username?: string;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  created_at: string; completed_at: string | null;
  progress: number; total: number;
  config: Omit<SimulationOptions, 'passwords' | 'probe'> & { customWordlist: boolean; customProbe?: boolean };
  report: SimulationReport | null; error: string | null;
}

