import axe from 'axe-core'
import { vi } from 'vitest'
import { setSessionSecret } from '../api/client'
import type { ApprovalDetail, ApprovalQueueItem, Authorization, Grant, Machine, Session, Settings, Status } from '../api/types'

export type Call = { method: string; path: string; query: URLSearchParams; body: Record<string, unknown> | null; headers: Record<string, string> }
export type Reply = { status?: number; body: unknown; problem?: boolean }
export type Handler = Reply | ((call: Call) => Reply)

export type FakeApi = { calls: Call[]; handlers: Record<string, Handler>; on: (route: string, handler: Handler) => void; count: (route: string) => number }

/** A stand-in for the service: routes are "METHOD /path" (query ignored); every call is recorded. An unknown route is a test failure. */
export function installFakeApi(handlers: Record<string, Handler>): FakeApi {
  const api: FakeApi = {
    calls: [],
    handlers: { ...handlers },
    on: (route, handler) => {
      api.handlers[route] = handler
    },
    count: (route) => api.calls.filter((call) => call.method + ' ' + call.path === route).length,
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), 'http://localhost:8765')
      const call: Call = {
        method: (init?.method ?? 'GET').toUpperCase(),
        path: url.pathname,
        query: url.searchParams,
        body: init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : null,
        headers: Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>)),
      }
      api.calls.push(call)
      const handler = api.handlers[call.method + ' ' + call.path]
      if (!handler) throw new Error(`no fake route for ${call.method} ${call.path}`)
      const reply = typeof handler === 'function' ? handler(call) : handler

      return new Response(JSON.stringify(reply.body), { status: reply.status ?? 200, headers: { 'content-type': reply.problem ? 'application/problem+json' : 'application/json' } })
    }),
  )

  return api
}

export function problem(status: number, code: string, detail: string): Reply {
  return { status, problem: true, body: { type: 'urn:with-secrets:problem:' + code, title: 'Refused', status, detail, code } }
}

export const status = (extra: Partial<Status> = {}): Status => ({ running: true, locked: false, unlockMode: 'manual', apiVersion: 'v1', version: __APP_VERSION__, protocolVersion: 1, ...extra })

export const session = (extra: Partial<Session> = {}): Session => ({
  authenticated: true,
  admin: 'admin key',
  identity: null,
  scope: null,
  capabilities: [],
  started: '2026-11-09T10:00:00Z',
  idleExpires: '2026-11-09T10:15:00Z',
  absoluteExpires: '2026-11-09T18:00:00Z',
  login: null,
  recent: [],
  ...extra,
})

export const machine = (extra: Partial<Machine> = {}): Machine => ({
  fingerprint: 'ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12',
  display: 'ab12 cd34 ef56 ab12',
  status: 'pending',
  revision: 1,
  hostName: 'build-host',
  pendingHostName: null,
  friendlyName: null,
  created: '2026-11-08T10:00:00Z',
  updated: '2026-11-08T10:00:00Z',
  thisMachine: false,
  actions: ['approve', 'rename'],
  copyWarning: null,
  ...extra,
})

export const grant = (extra: Partial<Grant> = {}): Grant => ({
  id: 'grant-0001',
  fingerprint: machine().fingerprint,
  machineName: 'build-host',
  state: 'active',
  status: 'active',
  revision: 1,
  created: '2026-11-09T09:00:00Z',
  updated: '2026-11-09T09:00:00Z',
  expires: '2026-11-09T12:00:00Z',
  ends: 'in 2 hours',
  secretNames: 'DEPLOY_TOKEN',
  program: 'deploy.cmd',
  workingDirectory: 'C:\\work',
  approvedBy: 'admin key',
  revoked: null,
  actions: ['extend', 'revoke'],
  ...extra,
})

export const settings = (extra: Partial<Settings> = {}): Settings => ({
  unlockMode: 'manual',
  unlockModeDescription: 'Manual. An administrator unlocks it with a passkey.',
  auditRetentionDays: 90,
  sessionIdleMinutes: 15,
  sessionAbsoluteMinutes: 480,
  authorityKey: 'AA11 BB22 CC33 DD44',
  maxAuditRetentionDays: 36500,
  maxSessionIdleMinutes: 120,
  maxSessionAbsoluteMinutes: 1440,
  ...extra,
})

export const authorization = (extra: Partial<Authorization> = {}): Authorization => ({
  id: 'auth-id-0001',
  operation: 'machine-approve',
  state: 'pending',
  detail: null,
  link: 'http://localhost:54321/passkey-page-token',
  sentence: 'Approve this machine ab12 cd34 ef56 ab12 as "ci box".',
  parameters: [],
  created: '2026-11-09T10:00:00Z',
  expires: '2026-11-09T10:10:00Z',
  lifetimeSeconds: 120,
  result: null,
  proof: null,
  ...extra,
})

/** The usual signed-in state of the service. */
/** A page that was signed in earlier in its life: it holds the session's secret (given once by the claim). */
export const SESSION_SECRET = 'session-secret-1'

export function signedIn(extra: Record<string, Handler> = {}): FakeApi {
  setSessionSecret(SESSION_SECRET)

  return installFakeApi({
    'GET /api/v1/status': { body: status() },
    'GET /api/v1/session': { body: session() },
    'GET /api/v1/machines': { body: { items: [machine()] } },
    'GET /api/v1/pairing/invitations': { body: { items: [] } },
    'GET /api/v1/grants': { body: { items: [grant()] } },
    'GET /api/v1/settings': { body: settings() },
    'GET /api/v1/page-settings': { body: { reuseMaxMinutes: 480, baseUrl: null, port: 0, timeoutMinutes: 5 } },
    'GET /api/v1/passkeys': { body: { available: true, problem: null, items: [{ name: 'admin key', detail: 'platform passkey', created: '2026-11-01T10:00:00Z', admin: true }] } },
    'GET /api/v1/approvals': { body: { items: [], nextCursor: null, serverTime: '2026-11-09T10:00:00Z' } },
    'GET /api/v1/audit/events': { body: { items: [] } },
    'GET /api/v1/audit/changes': { body: { items: [] } },
    'GET /api/v1/audit/gaps': { body: { items: [] } },
    // The service prepares the challenge for whatever operation was asked, as it does when a dialog opens.
    'POST /api/v1/authorizations/inline': (call) => ({
      status: 201,
      body: authorization({
        operation: String(call.body?.operation) as Authorization['operation'],
        link: null,
        proof: { mode: 'webauthn', payload: JSON.stringify({ bind: 'AQ', rpId: 'localhost', timeout: 60000 }) },
        parameters: Object.entries((call.body?.parameters ?? {}) as Record<string, unknown>).map(([name, value]) => ({ name, value: String(value) })),
      }),
    }),
    'GET /api/v1/authorizations/auth-id-0001': { body: authorization({ link: null }) },
    'DELETE /api/v1/authorizations/auth-id-0001': { body: { ok: true } },
    ...extra,
  })
}

/** Accessibility violations by axe-core (colour contrast needs a real browser: the E2E run checks that). */
export async function violations(root: Element): Promise<string[]> {
  const result = await axe.run(root, { rules: { 'color-contrast': { enabled: false } } })

  return result.violations.map((violation) => `${violation.id}: ${violation.help} (${violation.nodes.map((node) => node.target.join(' ')).join(', ')})`)
}

export const approvalItem = (extra: Partial<ApprovalQueueItem> = {}): ApprovalQueueItem => ({
  requestId: 'req-0001',
  status: 'pending',
  submittedAt: '2026-11-09T10:00:00Z',
  expiresAt: '2026-11-09T10:05:00Z',
  machine: { fingerprint: 'ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12', friendlyName: 'build box', hostName: 'build-host' },
  program: 'deploy.cmd',
  reason: 'ship the release',
  secretNames: ['DEPLOY_TOKEN'],
  ...extra,
})

export const approvalDetail = (extra: Partial<ApprovalDetail> = {}): ApprovalDetail => {
  const item = approvalItem()

  return {
    requestId: item.requestId,
    status: 'pending',
    submittedAt: item.submittedAt,
    expiresAt: item.expiresAt,
    decidedAt: null,
    machine: item.machine,
    program: item.program,
    reason: item.reason,
    secretNames: item.secretNames,
    decisionInProgress: false,
    actions: ['approve', 'deny'],
    review: {
      requestId: item.requestId,
      fingerprintKey: 'ab12',
      requestDigest: 'digest-0001',
      submittedAt: item.submittedAt,
      expiresAt: item.expiresAt,
      machine: item.machine,
      program: item.program,
      resolvedProgram: '/tools/deploy.cmd',
      arguments: ['--prod'],
      workingDirectory: '/work',
      reason: item.reason,
      secretNames: item.secretNames,
      secretSources: {},
      inlineCode: null,
      script: { path: '/tools/deploy.cmd', sha256: 'abcd', length: 12, text: 'echo deploying', guessed: false, binary: false },
      programFile: null,
      envFiles: [],
      envPairs: [],
      shownEnvValues: [],
      codeChangeWarnings: [],
      decrypts: [],
      inheritedEnvironmentLine: null,
      extraLines: [],
      canonicalText: 'text',
      requiresUnlock: false,
      heading: null,
      times: null,
      allowOnce: true,
    },
    ...extra,
  }
}
