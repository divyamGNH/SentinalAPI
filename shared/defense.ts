export interface DecisionEvidence {
  rule: string;
  field: string;
  explanation: string;
  counter?: { count: number; limit: number; windowSeconds: number; unit: string };
}

export const reviewVerdicts = ['needs_review', 'confirmed', 'false_positive'] as const;
export type ReviewVerdict = typeof reviewVerdicts[number];
export const reviewLabels: Record<ReviewVerdict, string> = {
  needs_review: 'Needs review',
  confirmed: 'Confirmed detection',
  false_positive: 'False positive',
};

export interface ReviewSummary {
  detector: string;
  total: number;
  confirmed: number;
  falsePositive: number;
  needsReview: number;
}

export interface RuleComparison {
  suite: string;
  before: string;
  after: string;
  rows: Array<{
    id: string;
    title: string;
    expected: boolean;
    before: boolean;
    after: boolean;
    change: 'improved' | 'regressed' | 'unchanged';
  }>;
}

export interface AuditVerification {
  valid: boolean;
  checked: number;
  legacyThrough: string;
  problem?: string;
}
