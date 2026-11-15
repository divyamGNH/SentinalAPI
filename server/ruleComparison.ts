import type { Request } from 'express';
import { buildPlan, parseOptions } from '../attack-sim/catalog';
import type { RuleComparison } from '../shared/defense';
import { matchesSqlSignature } from './detectors/sqli';
import { requestPayloads } from './payloads';

export function compareSqlRules(): RuleComparison {
  const { cases } = buildPlan(parseOptions({ scenarios: ['benign', 'sqli'] }));
  const rows: RuleComparison['rows'] = cases.flatMap(test => {
    const url = new URL(test.path, 'http://localhost');
    if (url.pathname !== '/search') return [];

    const query = Object.fromEntries(url.searchParams);
    const values = requestPayloads({ query, body: test.body } as Request).map(item => item.value);
    const expected = test.scenario === 'sqli';
    const before = values.some(value => value.includes("'"));
    const after = values.some(matchesSqlSignature);
    const change = before === after ? 'unchanged' : after === expected ? 'improved' : 'regressed';

    return [{
      id: test.id,
      title: test.benign && query.q ? `Normal search: ${query.q}` : test.name,
      expected, before, after, change,
    }];
  });

  return {
    suite: 'Standard search fixtures',
    before: 'Practice rule: flag any apostrophe',
    after: 'SentinelAPI SQL signature',
    rows,
  };
}
