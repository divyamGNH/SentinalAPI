import type { ReviewVerdict } from '../../shared/defense';
import type { Alert } from './types';

export type Connection = { api: string; token: string };

export async function requestDefense<T>(api: string, token: string, path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(api + path, {
    ...init,
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json', ...init?.headers },
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'The request failed.');
  return data;
}

export function saveReview(connection: Connection, id: Alert['id'], verdict: ReviewVerdict) {
  return requestDefense<Alert>(connection.api, connection.token, '/defense/alerts/' + id + '/review', {
    method: 'PATCH', body: JSON.stringify({ verdict }),
  });
}
