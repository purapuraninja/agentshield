const TOKEN_KEY = 'agentshield.token';

export const apiUrl = (import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:4141').replace(/\/$/, '');

export function getToken(): string {
  try { return localStorage.getItem(TOKEN_KEY) ?? ''; } catch { return ''; }
}

export function setToken(token: string): void {
  try {
    if (token.trim()) localStorage.setItem(TOKEN_KEY, token.trim());
    else localStorage.removeItem(TOKEN_KEY);
  } catch { /* storage unavailable */ }
}

/** Headers object for an authenticated request. Public paths may still be called unauthenticated. */
export function authHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const token = getToken();
  return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
}

/**
 * Fetch against the configured API URL with the stored bearer token attached when present.
 * Pass headers as a plain `Record<string, string>` object so the bearer token can be merged in.
 */
export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const plain: Record<string, string> = {};
  if (init.headers) {
    const source = init.headers instanceof Headers ? init.headers : new Headers(init.headers as Record<string, string>);
    source.forEach((value, key) => { plain[key] = value; });
  }
  return fetch(`${apiUrl}${path}`, { ...init, headers: authHeaders(plain) });
}

/** Maps a failed API response to a human-readable message, with a hint when auth is missing. */
export async function apiErrorMessage(response: Response, fallback: string): Promise<string> {
  if (response.status === 401) return 'Unauthorized — set your AgentShield API token in the header above.';
  try {
    const data = await response.json() as { error?: { message?: string } };
    return data.error?.message ?? fallback;
  } catch { return fallback; }
}
