export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, message: string, body: unknown = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

export class UnauthenticatedError extends ApiError {
  constructor(body: unknown = null) {
    super(401, 'unauthenticated', body);
    this.name = 'UnauthenticatedError';
  }
}

interface ApiFetchOptions extends RequestInit {
  /**
   * What to do on a 401. 'redirect' (default) performs a full-page navigation to /login
   * (login is an OAuth redirect flow). 'throw' raises UnauthenticatedError instead — used
   * by the session query so the SPA can render the login screen.
   */
  on401?: 'redirect' | 'throw';
}

async function parseJsonBody(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function filenameFromContentDisposition(header: string | null): string | null {
  if (!header) return null;
  const match = /filename="?([^";]+)"?/i.exec(header);
  return match ? match[1] : null;
}

/**
 * Fetch a file-producing endpoint and hand the result to the browser as a download.
 * Used where the response depends on a POST (e.g. cert generation), so a plain
 * <a href> link can't carry the request. Errors surface as ApiError with the
 * endpoint's text/plain body as the message.
 */
export async function apiDownload(
  path: string,
  fallbackName: string,
  options: ApiFetchOptions = {}
): Promise<void> {
  const { on401 = 'redirect', ...init } = options;

  const response = await fetch(path, init);

  if (response.status === 401) {
    if (on401 === 'redirect') {
      window.location.assign('/login');
      return new Promise<void>(() => {}); // never settles; the page is navigating away
    }
    throw new UnauthenticatedError();
  }

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new ApiError(response.status, body || `Request failed with status ${response.status}`);
  }

  const blob = await response.blob();
  const filename =
    filenameFromContentDisposition(response.headers.get('Content-Disposition')) ?? fallbackName;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export async function apiFetch<T>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  const { on401 = 'redirect', headers, ...init } = options;

  const response = await fetch(path, {
    ...init,
    headers: { Accept: 'application/json', ...headers },
  });

  if (response.status === 401) {
    if (on401 === 'redirect') {
      window.location.assign('/login');
      return new Promise<T>(() => {}); // never settles; the page is navigating away
    }
    throw new UnauthenticatedError(await parseJsonBody(response));
  }

  if (!response.ok) {
    const body = await parseJsonBody(response);
    let message = `Request failed with status ${response.status}`;
    if (body && typeof body === 'object' && 'error' in body && typeof body.error === 'string') {
      message = body.error;
    }
    throw new ApiError(response.status, message, body);
  }

  return (await response.json()) as T;
}
