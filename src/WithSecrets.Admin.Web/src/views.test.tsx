import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { setBrowserSecret } from './api/client'
import { authorization, grant, installFakeApi, machine, problem, session, signedIn, status, violations } from './test/fakeApi'
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
            { eventId: 'e1', sequence: 1, time: '2026-11-09T10:00:00Z', received: '2026-11-09T10:00:01Z', machine: 'ab12', type: 'launch', outcome: 'started', reason: '', requestId: 'r1', folder: 'C:\\work', program: 'deploy.cmd', arguments: ['--flag'], grantId: '', exitCode: null, metadata: { secrets: 'DB_URL', key: '<b>laptop</b>' } },
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

  it('shows the metadata of an audit event as read-only text, never as markup', async () => {
    signedIn({
      'GET /api/v1/audit/events': {
        body: {
          items: [
            { eventId: 'e1', sequence: 1, time: '2026-11-09T10:00:00Z', received: '2026-11-09T10:00:01Z', machine: 'ab12', type: 'admin', outcome: 'secrets-set', reason: '', requestId: '', folder: '', program: '', arguments: [], grantId: '', exitCode: null, metadata: { key: '<img src=x onerror=alert(1)>', names: 'DB_URL' } },
          ],
        },
      },
    })
    const { container } = renderApp('/audit')
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(screen.getByText('Metadata: names')).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
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

  it('opens the compact navigation and Escape closes it with focus returned to the menu button', async () => {
    const user = userEvent.setup()
    signedIn()
    renderApp('/machines')
    const menu = await screen.findByRole('button', { name: 'Menu' })

    expect(menu).toHaveAttribute('aria-expanded', 'false')
    await user.click(menu)
    expect(menu).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('link', { name: 'Passkeys' })).toBeInTheDocument()

    await user.keyboard('{Escape}')
    expect(menu).toHaveAttribute('aria-expanded', 'false')
    expect(menu).toHaveFocus()
  })

  it('closes the compact navigation after choosing a destination', async () => {
    const user = userEvent.setup()
    signedIn()
    renderApp('/machines')
    const menu = await screen.findByRole('button', { name: 'Menu' })
    await user.click(menu)
    await user.click(screen.getByRole('link', { name: 'Grants' }))

    expect(await screen.findByRole('heading', { level: 1, name: 'Grants' })).toBeInTheDocument()
    expect(menu).toHaveAttribute('aria-expanded', 'false')
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

describe('machine identity details', () => {
  it('keeps the compact fingerprint visible and lets the full fingerprint be inspected', async () => {
    const user = userEvent.setup()
    signedIn()
    renderApp('/machines')
    await screen.findByRole('heading', { name: 'build-host' })

    await user.click(screen.getByText('Show full fingerprint'))
    expect(screen.getByText(machine().fingerprint)).toBeInTheDocument()
  })
})

describe('the overview', () => {
  it('keeps active grants as a neutral summary rather than an attention condition', async () => {
    signedIn()
    renderApp('/')

    const activeGrant = await screen.findByRole('link', { name: '1 active grant' })
    expect(activeGrant.closest('li')).toBeNull()
  })

  it('shows recoverable errors instead of leaving optional data in a loading state', async () => {
    signedIn({
      'GET /api/v1/machines': problem(503, 'machines-unavailable', 'machines are unavailable'),
      'GET /api/v1/grants': problem(503, 'grants-unavailable', 'grants are unavailable'),
    })
    renderApp('/')

    const alerts = await screen.findAllByRole('alert', {}, { timeout: 4000 })
    expect(alerts.map((alert) => alert.textContent).join(' ')).toContain('Machine attention could not be loaded')
    expect(alerts.map((alert) => alert.textContent).join(' ')).toContain('Active grants could not be loaded')
    expect(screen.queryByText('Machines: loading')).toBeNull()
    expect(screen.queryByText('Grants: loading')).toBeNull()
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
    const openSpy = vi.spyOn(window, 'open').mockReturnValue(null)
    const user = userEvent.setup()
    const fake = installFakeApi({
      'GET /api/v1/status': { body: status({ locked: true }) },
      'GET /api/v1/session': { body: signedOut() },
      'POST /api/v1/authorizations': { status: 201, body: authorization({ operation: 'unlock', parameters: [], sentence: 'Unlock the authority.' }) },
      'GET /api/v1/authorizations/auth-id-0001': { body: authorization({ operation: 'unlock', state: 'consumed', parameters: [], result: { outcome: 'applied', code: null, detail: null, link: null, invitation: null, invitationGone: false } }) },
    })
    renderApp('/')
    await user.click(await screen.findByRole('button', { name: 'Unlock the authority' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))

    // One step; the service makes the change at the tap, and this page only reads the result (no unlock call of its own).
    expect(await within(dialog).findByText('Done')).toBeInTheDocument()
    expect(fake.count('POST /api/v1/unlock')).toBe(0)
    expect(fake.calls.find((call) => call.path === '/api/v1/authorizations')?.body).toEqual({ operation: 'unlock', parameters: {} })
    expect(openSpy).toHaveBeenCalledOnce()
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
    expect(await screen.findByText('No events match these filters.')).toBeInTheDocument()
  })
})

describe('settings and passkey context', () => {
  it('keeps passkey administration context on the settings task that uses it', async () => {
    signedIn()
    renderApp('/settings')

    expect(await screen.findByRole('heading', { level: 1, name: 'Settings' })).toBeInTheDocument()
    const context = screen.getByText(/Manage the credentials that can administer this authority/)
    expect(within(context).getByRole('link', { name: 'Passkeys' })).toHaveAttribute('href', '/passkeys')
    expect(screen.queryByText(/Every change here needs its own fresh passkey tap/)).toBeNull()
  })

  it('explains credential role separately from credential kind on the passkeys page', async () => {
    signedIn()
    renderApp('/passkeys')

    expect(await screen.findByText(/Admin passkeys can administer this authority/)).toBeInTheDocument()
    expect(screen.getByText(/The kind describes the credential; the badge shows what it is allowed to do/)).toBeInTheDocument()
    const context = screen.getByText(/For authority behavior and signing-key maintenance/)
    expect(within(context).getByRole('link', { name: 'Settings' })).toHaveAttribute('href', '/settings')
  })
})

describe('grant and audit navigation', () => {
  it('links a grant to its host events and machine authority changes', async () => {
    signedIn({ 'GET /api/v1/grants': { body: { items: [grant()] } } })
    renderApp('/grants')

    expect(await screen.findByRole('link', { name: 'View events for this grant' })).toHaveAttribute('href', '/audit?grant=grant-0001')
    expect(screen.getByRole('link', { name: 'View changes for this machine' })).toHaveAttribute(
      'href',
      '/audit/changes?machine=' + grant().fingerprint,
    )
  })

  it('links audit records to filtered evidence and shows both event timestamps', async () => {
    signedIn({
      'GET /api/v1/audit/events': {
        body: {
          items: [{
            eventId: 'event-1',
            sequence: 12,
            time: '2026-11-09T10:00:00Z',
            received: '2026-11-09T10:00:03Z',
            machine: machine().fingerprint,
            type: 'launch',
            outcome: 'started',
            reason: '',
            requestId: 'request-1',
            folder: 'C:\\work',
            program: 'deploy.cmd',
            arguments: [],
            grantId: 'grant-0001',
            exitCode: null,
            metadata: {},
          }],
        },
      },
    })
    renderApp('/audit')

    expect(await screen.findByRole('link', { name: machine().fingerprint })).toHaveAttribute(
      'href',
      '/audit/changes?machine=' + machine().fingerprint,
    )
    expect(screen.getByRole('link', { name: 'grant-0001' })).toHaveAttribute('href', '/audit?grant=grant-0001')
    const times = Array.from(document.querySelectorAll('time')).map((time) => time.dateTime)
    expect(times).toContain('2026-11-09T10:00:00Z')
    expect(times).toContain('2026-11-09T10:00:03Z')
  })

  it('can clear URL-backed audit filters', async () => {
    const user = userEvent.setup()
    signedIn()
    renderApp('/audit?text=deploy.cmd')

    expect(await screen.findByLabelText(/contains text/i)).toHaveValue('deploy.cmd')
    await user.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(screen.getByLabelText(/contains text/i)).toHaveValue('')
    expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull()
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

  it('warns on a machine whose identity may have been copied, never by itself disabling it', async () => {
    signedIn({
      'GET /api/v1/machines': {
        body: { items: [machine({ status: 'trusted', actions: ['disable', 'rename'], copyWarning: { count: 3, firstAddress: '10.0.0.5', lastAddress: '10.0.0.9', firstSeen: '2026-11-09T10:00:00Z', lastSeen: '2026-11-09T10:04:00Z' } }), machine({ fingerprint: 'ff'.repeat(32), display: 'ffff', hostName: 'clean-host', status: 'trusted', actions: ['disable'] })] },
      },
    })
    renderApp('/machines')
    await screen.findByRole('heading', { name: 'clean-host' })

    expect(screen.getAllByText(/Disable this machine if you did not start both./)).toHaveLength(1)
    expect(screen.getByText(/10.0.0.9/)).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /^disable/i })).toHaveLength(2)
  })

  it('states the status in words as well as colour', async () => {
    signedIn({ 'GET /api/v1/status': { body: status({ locked: true }) } })
    renderApp('/')

    expect(await screen.findByText('Authority locked')).toBeInTheDocument()
  })
})
