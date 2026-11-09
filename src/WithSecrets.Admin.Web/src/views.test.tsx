import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { setBrowserSecret } from './api/client'
import { authorization, installFakeApi, machine, problem, session, signedIn, status, violations } from './test/fakeApi'
import { renderApp } from './test/render'

const signedOut = () => session({ authenticated: false, admin: null, started: null, idleExpires: null, absoluteExpires: null })

describe('the primary views have no automated accessibility violations', () => {
  const views: Array<[string, string, string]> = [
    ['overview', '/', 'Overview'],
    ['machines', '/machines', 'Machines'],
    ['grants', '/grants', 'Grants'],
    ['audit events', '/audit', 'Audit'],
    ['audit changes', '/audit/changes', 'Audit'],
    ['audit gaps', '/audit/gaps', 'Audit'],
    ['settings', '/settings', 'Settings'],
    ['passkeys', '/passkeys', 'Passkeys'],
  ]

  it.each(views)('%s', async (_name, route, heading) => {
    signedIn({
      'GET /api/v1/audit/events': {
        body: {
          items: [
            { eventId: 'e1', sequence: 1, time: '2026-11-09T10:00:00Z', received: '2026-11-09T10:00:01Z', machine: 'ab12', type: 'launch', outcome: 'started', reason: '', requestId: 'r1', folder: 'C:\\work', program: 'deploy.cmd', arguments: ['--flag'], grantId: '', exitCode: null },
          ],
        },
      },
      'GET /api/v1/audit/changes': { body: { items: [{ id: 1, time: '2026-11-09T10:00:00Z', event: 'machine-approve', machine: 'ab12', actor: 'admin passkey', detail: 'approved' }] } },
      'GET /api/v1/audit/gaps': { body: { items: [{ id: 1, machine: 'ab12', kind: 'missing', from: 3, to: 4, detected: '2026-11-09T10:00:00Z', resolved: null, epoch: 'e' }] } },
    })
    const { container } = renderApp(route)
    expect(await screen.findByRole('heading', { level: 1, name: heading })).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText(/^Loading/)).toBeNull())
    expect(await violations(container)).toEqual([])
  })

  it('the sign-in view', async () => {
    installFakeApi({ 'GET /api/v1/status': { body: status({ locked: true }) }, 'GET /api/v1/session': { body: signedOut() } })
    const { container } = renderApp('/')
    expect(await screen.findByRole('heading', { level: 1, name: 'Sign in' })).toBeInTheDocument()
    await screen.findByText('The authority is locked')
    expect(await violations(container)).toEqual([])
  })
})

describe('the shell', () => {
  it('has landmarks, a skip link and marks the current view with aria-current', async () => {
    signedIn()
    renderApp('/machines')
    await screen.findByRole('heading', { level: 1, name: 'Machines' })

    expect(screen.getByRole('link', { name: /skip to the main content/i })).toHaveAttribute('href', '#main')
    expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument()
    expect(screen.getByRole('main')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Machines' })).toHaveAttribute('aria-current', 'page')
    expect(document.title).toBe('Machines - with-secrets administration')
  })

  it('warns when the page and the service are different versions', async () => {
    signedIn({ 'GET /api/v1/status': { body: status({ version: '9.9.9' }) } })
    renderApp('/')

    expect(await screen.findByText(/different versions/)).toBeInTheDocument()
  })

  it("moves focus to the new view's heading after a navigation", async () => {
    const user = userEvent.setup()
    signedIn()
    renderApp('/')
    await screen.findByRole('heading', { level: 1, name: 'Overview' })
    await user.click(screen.getByRole('link', { name: 'Grants' }))

    await waitFor(() => expect(screen.getByRole('heading', { level: 1, name: 'Grants' })).toHaveFocus())
  })
})

describe('sign-in', () => {
  it('starts a read-only session with one tap on the service page and then shows the views', async () => {
    const user = userEvent.setup()
    let tapped = false
    let started = false
    let claimed = false
    setBrowserSecret(null)
    const fake = installFakeApi({
      'GET /api/v1/status': { body: status() },
      'GET /api/v1/session': () => ({ body: claimed ? session() : tapped ? { ...signedOut(), login: { state: 'ready', problem: null } } : started ? { ...signedOut(), login: { state: 'waiting', problem: null } } : signedOut() }),
      'POST /api/v1/browser': { status: 201, body: { antiForgery: 'browser-secret-1' } },
      'POST /api/v1/session': () => {
        started = true

        return { status: 202, body: { link: 'http://localhost:54321/login-page-token' } }
      },
      'POST /api/v1/session/claim': () => {
        claimed = true

        return { status: 201, body: { antiForgery: 'session-secret-1', session: session() } }
      },
      'GET /api/v1/machines': { body: { items: [machine({ status: 'trusted', actions: ['rename'] })] } },
      'GET /api/v1/grants': { body: { items: [] } },
    })
    renderApp('/machines')
    await user.click(await screen.findByRole('button', { name: 'Sign in' }))
    const open = await screen.findByRole('link', { name: /open the passkey page/i })
    expect(open).toHaveAttribute('href', 'http://localhost:54321/login-page-token')
    expect(fake.calls.find((call) => call.method === 'POST' && call.path === '/api/v1/session')?.headers['X-Admin-Token']).toBe('browser-secret-1')
    tapped = true

    expect(await screen.findByRole('heading', { level: 1, name: 'Machines' }, { timeout: 4000 })).toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: 'build-host' })).toBeInTheDocument()
    // The claim is a POST made by the page (the read of the session claims nothing), and from then on every request carries the session's own secret.
    expect(fake.calls.some((call) => call.method === 'POST' && call.path === '/api/v1/session/claim')).toBe(true)
    expect(fake.calls.filter((call) => call.path === '/api/v1/machines').every((call) => call.headers['X-Admin-Token'] === 'session-secret-1')).toBe(true)
  })

  it('does not accept a link that is not on this machine', async () => {
    const user = userEvent.setup()
    installFakeApi({
      'GET /api/v1/status': { body: status() },
      'GET /api/v1/session': { body: signedOut() },
      'POST /api/v1/browser': { status: 201, body: { antiForgery: 'browser-secret-1' } },
      'POST /api/v1/session': { status: 202, body: { link: 'https://evil.example/login' } },
    })
    renderApp('/')
    await user.click(await screen.findByRole('button', { name: /sign in/i }))

    await waitFor(() => expect(screen.queryByRole('link', { name: /open the passkey page/i })).toBeNull())
  })

  it('shows a sign-out that ends the session', async () => {
    const user = userEvent.setup()
    let out = false
    const fake = signedIn({
      'GET /api/v1/session': () => ({ body: out ? signedOut() : session() }),
      'DELETE /api/v1/session': () => {
        out = true

        return { body: { ok: true } }
      },
    })
    renderApp('/')
    await user.click(await screen.findByRole('button', { name: 'Sign out' }))

    expect(await screen.findByRole('heading', { level: 1, name: 'Sign in' })).toBeInTheDocument()
    expect(fake.calls.find((call) => call.method === 'DELETE')?.headers['X-Admin-Token']).toBe('session-secret-1')
  })

  it('shows the sign-in when a view answers 401 (the session ended)', async () => {
    let ended = false
    signedIn({
      'GET /api/v1/session': () => ({ body: ended ? signedOut() : session() }),
      'GET /api/v1/machines': () => {
        ended = true

        return problem(401, 'session-required', 'this needs an administrator session')
      },
    })
    renderApp('/machines')

    expect(await screen.findByRole('heading', { level: 1, name: 'Sign in' })).toBeInTheDocument()
  })
})

describe('the locked authority', () => {
  it('can be unlocked without a session, with its own authorization', async () => {
    const user = userEvent.setup()
    const fake = installFakeApi({
      'GET /api/v1/status': { body: status({ locked: true }) },
      'GET /api/v1/session': { body: signedOut() },
      'POST /api/v1/authorizations': { status: 201, body: authorization({ operation: 'unlock', parameters: [], sentence: 'Unlock the authority.' }) },
      'GET /api/v1/authorizations/auth-id-0001': { body: authorization({ operation: 'unlock', state: 'verified', parameters: [] }) },
      'POST /api/v1/unlock': { body: { operation: 'unlock', outcome: 'applied', link: null } },
    })
    renderApp('/')
    await user.click(await screen.findByRole('button', { name: 'Unlock the authority' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: /ask for passkey authorization/i }))

    await waitFor(() => expect(fake.count('POST /api/v1/unlock')).toBe(1))
    expect(fake.calls.find((call) => call.path === '/api/v1/unlock')?.body).toEqual({ authorization: 'auth-id-0001' })
  })
})

describe('audit search', () => {
  it('puts the search in the address and asks the service with the filters', async () => {
    const user = userEvent.setup()
    const fake = signedIn()
    renderApp('/audit')
    await user.type(await screen.findByLabelText(/contains text/i), 'deploy.cmd')
    await user.selectOptions(screen.getByLabelText(/kind of event/i), 'launch')
    await user.click(screen.getByRole('button', { name: 'Search' }))

    await waitFor(() => {
      const last = fake.calls.filter((call) => call.path === '/api/v1/audit/events').at(-1)
      expect(last?.query.get('text')).toBe('deploy.cmd')
      expect(last?.query.get('type')).toBe('launch')
    })
    expect(await screen.findByText('No events found.')).toBeInTheDocument()
  })
})

describe('what is shown', () => {
  it('lists machines with the actions each one offers', async () => {
    signedIn({ 'GET /api/v1/machines': { body: { items: [machine(), machine({ fingerprint: 'ff'.repeat(32), display: 'ffff', status: 'trusted', friendlyName: 'ci box', actions: ['disable', 'untrust', 'rename'] })] } } })
    renderApp('/machines')
    await screen.findByRole('heading', { name: 'ci box' })

    expect(screen.getByRole('button', { name: /^approve/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^disable/i })).toBeInTheDocument()
  })

  it('states the status in words as well as colour', async () => {
    signedIn({ 'GET /api/v1/status': { body: status({ locked: true }) } })
    renderApp('/')

    expect(await screen.findAllByText('Locked')).not.toHaveLength(0)
  })
})
