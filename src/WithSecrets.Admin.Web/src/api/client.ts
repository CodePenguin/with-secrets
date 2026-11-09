import type { paths } from './schema'

/**
 * The thin typed fetch wrapper over the generated types (schema.ts). It knows nothing about screens.
 * - Same origin only (relative URLs), cookies of this origin only.
 * - A session is its cookie AND a secret that the service gives once (POST /session/claim; before a session POST /browser gives the browser's). The cookie is sent to every localhost port by the browser, the
 *   secret is not: it is kept in this tab's sessionStorage (per origin, so per port; gone when the tab closes; never localStorage) so that a reload stays signed in, and is sent as X-Admin-Token on every
 *   request, reads included. The service never gives it a second time. It is the only thing the application keeps in browser storage.
 * - Every refusal becomes an ApiError that carries only what the problem document says (a safe sentence and a code).
 */

export const ANTI_FORGERY_HEADER = 'X-Admin-Token'

type Method = 'get' | 'post' | 'put' | 'delete'
type PathsWith<M extends Method> = { [P in keyof paths]: paths[P] extends { [K in M]: object } ? P : never }[keyof paths]
type Operation<P extends keyof paths, M extends Method> = paths[P] extends { [K in M]: infer O } ? O : never
type PathParams<O> = O extends { parameters: { path: infer X } } ? X : never
type QueryParams<O> = O extends { parameters: { query?: infer Q } } ? NonNullable<Q> : never
type JsonBody<O> = O extends { requestBody: { content: { 'application/json': infer B } } } ? B : never
type Responses<O> = O extends { responses: infer R } ? R : never
type SuccessStatus = 200 | 201 | 202
type Success<O> = {
  [S in SuccessStatus & keyof Responses<O>]: Responses<O>[S] extends { content: { 'application/json': infer B } } ? B : never
}[SuccessStatus & keyof Responses<O>]

type Init<O> = ([PathParams<O>] extends [never] ? { path?: undefined } : { path: PathParams<O> }) &
  ([QueryParams<O>] extends [never] ? { query?: undefined } : { query?: QueryParams<O> }) &
  ([JsonBody<O>] extends [never] ? { body?: undefined } : { body: JsonBody<O> }) & { signal?: AbortSignal }

/** A refusal or failure, as the service reports it (RFC 9457 problem) or as the network shows it (status 0). */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly title: string

  constructor(status: number, code: string, title: string, detail: string) {
    super(detail)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.title = title
  }
}

const BROWSER_PATH = '/api/v1/browser'

const SESSION_KEY = 'ws.session-secret'
const BROWSER_KEY = 'ws.browser-secret'

function read(key: string): string | null {
  try {
    // eslint-disable-next-line no-restricted-globals -- the one place the application uses browser storage: the two secrets, for this tab only
    return sessionStorage.getItem(key)
  } catch {
    return null
  }
}

function write(key: string, value: string | null): void {
  try {
    // eslint-disable-next-line no-restricted-globals -- see read()
    if (value === null) sessionStorage.removeItem(key)
    // eslint-disable-next-line no-restricted-globals -- see read()
    else sessionStorage.setItem(key, value)
  } catch {
    // Storage is not available: the secret is then lost on reload, and the page signs in again.
  }
}

/** The session's own secret (given once by the claim), or null. */
export function setSessionSecret(value: string | null): void {
  write(SESSION_KEY, value)
}

/** The browser's secret (given once by POST /browser, before a session), or null. */
export function setBrowserSecret(value: string | null): void {
  write(BROWSER_KEY, value)
}

/** What is sent as the header: the session's secret while there is one, else the browser's. */
export function currentSecret(): string | null {
  return read(SESSION_KEY) ?? read(BROWSER_KEY)
}

let making: Promise<void> | null = null

/** Makes the browser's identity (its pre-session cookie) and keeps the secret that comes with it. Once at a time. */
function ensureBrowser(): Promise<void> {
  making ??= (async () => {
    try {
      const made = (await send('post', BROWSER_PATH, { body: {} })) as { antiForgery: string }
      setBrowserSecret(made.antiForgery)
    } finally {
      making = null
    }
  })()

  return making
}

const MAX_DETAIL = 400

function safe(text: unknown, fallback: string): string {
  if (typeof text !== 'string' || text.length === 0) return fallback
  return text.length > MAX_DETAIL ? text.slice(0, MAX_DETAIL) + '...' : text
}

function expand(template: string, path: Record<string, unknown> | undefined): string {
  return template.replace(/\{([^}]+)\}/g, (_, name: string) => encodeURIComponent(String(path?.[name] ?? '')))
}

function search(query: Record<string, unknown> | undefined): string {
  if (!query) return ''
  const parts = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && String(value) !== '') parts.set(key, String(value))
  }
  const text = parts.toString()
  return text ? '?' + text : ''
}

async function send(method: Method, template: string, init: { path?: unknown; query?: unknown; body?: unknown; signal?: AbortSignal }, retried = false): Promise<unknown> {
  const headers: Record<string, string> = { Accept: 'application/json, application/problem+json' }
  let body: string | undefined
  if (method !== 'get') {
    // A change needs an identity: a browser with no secret yet (a new tab) makes its own first.
    if (template !== BROWSER_PATH && currentSecret() === null) await ensureBrowser()
    body = JSON.stringify(init.body ?? {})
    headers['Content-Type'] = 'application/json'
  }
  const secret = currentSecret()
  if (secret && template !== BROWSER_PATH) headers[ANTI_FORGERY_HEADER] = secret
  const url = expand(template, init.path as Record<string, unknown> | undefined) + search(init.query as Record<string, unknown> | undefined)

  let response: Response
  try {
    response = await fetch(url, { method: method.toUpperCase(), headers, body, credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: init.signal })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new ApiError(0, 'network', 'No answer', 'The service did not answer. Is it still running?')
  }

  const type = response.headers.get('content-type') ?? ''
  let data: unknown = null
  if (type.includes('json')) {
    try {
      data = await response.json()
    } catch {
      data = null
    }
  }
  if (!response.ok) {
    const problem = (data ?? {}) as Record<string, unknown>
    if (method !== 'get' && template !== BROWSER_PATH && !retried && response.status === 403 && problem.code === 'anti-forgery') {
      // The secret is not (any longer) the cookie's: forget what is kept, make the browser's identity again and try once more.
      setSessionSecret(null)
      setBrowserSecret(null)
      await ensureBrowser()

      return send(method, template, init, true)
    }
    throw new ApiError(response.status, safe(problem.code, 'error'), safe(problem.title, 'The request was refused'), safe(problem.detail, 'The service refused the request.'))
  }
  if (data === null) throw new ApiError(response.status, 'unexpected-response', 'Unexpected answer', 'The service answered in a form this page does not understand.')

  return data
}

export const api = {
  get<P extends PathsWith<'get'>>(path: P, ...init: [Init<Operation<P, 'get'>>?]): Promise<Success<Operation<P, 'get'>>> {
    return send('get', path, init[0] ?? {}) as Promise<Success<Operation<P, 'get'>>>
  },
  post<P extends PathsWith<'post'>>(path: P, init: Init<Operation<P, 'post'>>): Promise<Success<Operation<P, 'post'>>> {
    return send('post', path, init) as Promise<Success<Operation<P, 'post'>>>
  },
  put<P extends PathsWith<'put'>>(path: P, init: Init<Operation<P, 'put'>>): Promise<Success<Operation<P, 'put'>>> {
    return send('put', path, init) as Promise<Success<Operation<P, 'put'>>>
  },
  delete<P extends PathsWith<'delete'>>(path: P, init: Init<Operation<P, 'delete'>>): Promise<Success<Operation<P, 'delete'>>> {
    return send('delete', path, init) as Promise<Success<Operation<P, 'delete'>>>
  },
}
