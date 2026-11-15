export interface DecisionEvidence {
  rule: string;
  field: string;
  explanation: string;
  counter?: { count: number; limit: number; windowSeconds: number; unit: string };
}
