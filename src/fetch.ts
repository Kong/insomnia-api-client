export function isLocalhost() {
  return window.location.hostname === 'localhost';
}

export function isStaging() {
  return window.location.hostname === 'app.insomnia.moe';
}

export function isPreview() {
  return /-teaminsomnia\.vercel\.app$/.test(window.location.hostname);
}

export function post<T>(path: string, obj?: unknown) {
  return _fetch<T>('POST', path, obj);
}

export function put<T>(path: string, obj?: unknown) {
  return _fetch<T>('PUT', path, obj);
}

export function patch<T>(path: string, obj?: unknown) {
  return _fetch<T>('PATCH', path, obj);
}

export function get<T>(path: string, authenticated = true) {
  return _fetch<T>('GET', path, null, authenticated);
}

export function del<T>(path: string) {
  return _fetch<T>('DELETE', path, null);
}

async function _fetch<T = unknown>(method: string, path: string, json: unknown, authenticated = true): Promise<T> {
  const headers = new Headers();

  if (json) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(_getUrl(path), {
    headers,
    method,
    ...(authenticated ? { credentials: 'include' } : {}),
    ...(json ? { body: JSON.stringify(json, null, 2) } : {}),
  });

  if (!response.ok) {
    const err = new Error(`Response ${response.status} for ${path}`);
    err.message = await response.text();
    throw err;
  }

  if (response.headers.get('content-type') === 'application/json') {
    return response.json();
  } else {
    throw new Error(`Unexpected content-type for ${path}`);
  }
}

export function _getUrl(path: string) {
  if (isLocalhost()) {
    return `http://localhost:8000${path}`;
  } else if (isStaging()) {
    return `https://api.insomnia.moe${path}`;
  } else if (isPreview()) {
    return `https://api.dev.insomnia.moe${path}`;
  } else {
    return `https://api.insomnia.rest${path}`;
  }
}