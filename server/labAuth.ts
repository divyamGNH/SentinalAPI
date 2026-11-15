export function validLabLogin(body: unknown): boolean {
  const input = body as { username?: unknown; password?: unknown } | undefined;
  return input?.username === 'admin' && input.password === 'password123';
}
