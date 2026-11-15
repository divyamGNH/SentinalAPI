const expected = test.scenario === 'sqli';
const before = values.some(value => value.includes("'"));
const after = values.some(matchesSqlSignature);
const change = before === after ? 'unchanged' : after === expected ? 'improved' : 'regressed';
