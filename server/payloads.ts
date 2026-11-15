import { Request } from 'express';

export function normalize(value: string): string {
  let result = value.slice(0, 16_384);
  for (let i = 0; i < 3; i++) {
    try {
      const decoded = decodeURIComponent(result);
      if (decoded === result) break;
      result = decoded;
    } catch { break; }
  }
  return result.replace(/&#x([0-9a-f]+);?/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
    .replace(/&#(\d+);?/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&quot;/gi, '"');
}

export function requestPayloads(req: Request, includeUrl = false) {
  const output: Array<{ value: string; field: string; sensitive: boolean }> = [];
  const visit = (value: unknown, field: string, sensitive = false, depth = 0) => {
    if (output.length >= 200 || depth > 8) return;
    if (typeof value === 'string') {
      const label = sensitive && field !== 'Request URL' ? 'Sensitive request field' : field.slice(0, 160);
      output.push({ value: normalize(value), field: label, sensitive });
    } else if (value && typeof value === 'object') {
      for (const [key, item] of Object.entries(value)) {
        if (output.length >= 200) break;
        visit(item, field + '.' + key.slice(0, 32), sensitive || /password|token|authorization|secret|cookie/i.test(key), depth + 1);
      }
    }
  };
  // URL evidence carries only a location label because it can contain arbitrary credentials.
  if (includeUrl) visit(req.originalUrl, 'Request URL', true);
  const urlEvidence = output[0];
  visit(req.query, 'query');
  visit(req.body, 'body');
  visit(req.params, 'params');
  return urlEvidence ? [...output.slice(1), urlEvidence] : output;
}
