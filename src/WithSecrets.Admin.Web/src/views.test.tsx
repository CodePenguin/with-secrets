import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { setBrowserSecret } from './api/client'
import { authorization, grant, installFakeApi, machine, problem, session, settings, signedIn, status, violations } from './test/fakeApi'
import { renderApp } from './test/render'

const signedOut = () => session({ authenticated: false, scope: null, capabilities: [], admin: null, started: null, idleExpires: null, absoluteExpires: null })

describe('the primary views have no automated accessibility violations', () => {
  const views: Array<[string, string, string]> = [
    ['overview', '/', 'Overview'],
    ['machines', '/machines', 'Machines'],
    ['access', '/access', 'Access'],
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
    await userEvent.setup().click(await screen.findByRole('button', { name: /View secrets-set event/ }))
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(screen.getByText('Metadata: names')).toBeInTheDocument()
    expect(container.querySelector('main img')).toBeNull() // the logo in the header is an image; the audit text is not
  })

  it('the sign-in view', async () => {
    installFakeApi({ 'GET /api/v1/status': { body: status({ locked: true }) }, 'GET /api/v1/session': { body: signedOut() } })
    const { container } = renderApp('/sign-in')
    expect(await screen.findByRole('heading', { level: 1, name: 'with-secrets' })).toBeInTheDocument()
    await screen.findByText('The authority is locked')
    expect(await violations(container)).toEqual([])
  })
})

describe('the shell', () => {
  it('directs remote hosts to the authority without asking for sign-in or unlock', async () => {
    const fake = installFakeApi({
      'GET /api/v1/status': { body: status({ remote: true }) },
      'GET /api/v1/session': { body: signedOut() },
    })
    renderApp('/')

    expect(await screen.findByText('Open the administration app on the authority to manage access and secrets.')).toBeInTheDocument()
    expect(screen.getByText('Remote host')).toBeInTheDocument()
    expect(screen.queryByText(/Authority (locked|unlocked)/)).toBeNull()
    expect(screen.queryByRole('button', { name: /sign in|unlock|lock the authority/i })).toBeNull()
    expect(fake.count('POST /api/v1/session/inline')).toBe(0)
  })

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
    await user.click(screen.getByRole('link', { name: 'Access' }))

    expect(await screen.findByRole('heading', { level: 1, name: 'Access' })).toBeInTheDocument()
    expect(menu).toHaveAttribute('aria-expanded', 'false')
  })

  it("moves focus to the new view's heading after a navigation", async () => {
    const user = userEvent.setup()
    signedIn()
    renderApp('/')
    await screen.findByRole('heading', { level: 1, name: 'Overview' })
    await user.click(screen.getByRole('link', { name: 'Access' }))

    await waitFor(() => expect(screen.getByRole('heading', { level: 1, name: 'Access' })).toHaveFocus())
  })
})

describe('machine identity details', () => {
  it('keeps the compact fingerprint visible and lets the full fingerprint be inspected', async () => {
    const user = userEvent.setup()
    signedIn()
    renderApp('/machines')
    await user.click(await screen.findByRole('button', { name: /build-host.*View machine/ }))

    await user.click(screen.getByText('Show full fingerprint'))
    expect(screen.getByText(machine().fingerprint)).toBeInTheDocument()
  })

  it('keeps a long friendly name, reported host name and complete fingerprint readable together', async () => {
    const user = userEvent.setup()
    const friendlyName = 'analytics-render-farm-' + 'x'.repeat(80)
    const hostName = 'render-farm-' + 'y'.repeat(80)
    const reported = 'new-' + 'z'.repeat(80)
    signedIn({
      'GET /api/v1/machines': {
        body: { items: [machine({ status: 'trusted', friendlyName, hostName, pendingHostName: reported, actions: ['approve-host-change', 'rename'] })] },
      },
    })
    renderApp('/machines')
    await user.click(await screen.findByRole('button', { name: /View machine/ }))
    const card = await screen.findByRole('dialog', { name: friendlyName })

    expect(within(card).getByText(hostName)).toBeInTheDocument()
    expect(within(card).getByText(reported)).toBeInTheDocument()
    await user.click(within(card).getByText('Show full fingerprint'))
    expect(within(card).getByText(machine().fingerprint)).toBeInTheDocument()
  })
})

describe('the overview', () => {
  it('shows the consequence of a locked authority without repeating the shell status or session identity', async () => {
    signedIn({ 'GET /api/v1/status': { body: status({ locked: true }) } })
    renderApp('/')

    expect(await screen.findByRole('button', { name: 'Unlock the authority' })).toBeInTheDocument()
    expect(screen.getByText(/The authority is locked/)).toBeInTheDocument()
    expect(screen.getAllByText('Authority locked')).toHaveLength(1)
    expect(screen.queryByRole('heading', { name: 'Authority' })).toBeNull()
    expect(within(screen.getByRole('navigation', { name: 'Main' })).getByText('Version ' + __APP_VERSION__)).toBeInTheDocument()
    expect(screen.getAllByText(/Signed in/)).toHaveLength(1)
  })

  it('keeps active grants as a neutral summary rather than an attention condition', async () => {
    signedIn()
    renderApp('/')

    const active = await screen.findByRole('link', { name: '1 active grant' })
    const attention = screen.getByRole('heading', { name: 'Needs your attention' }).closest('section') as HTMLElement
    expect(within(attention).queryByRole('link', { name: /active grant/ })).toBeNull()
    const glance = screen.getByRole('heading', { name: 'At a glance' }).closest('section') as HTMLElement
    expect(within(glance).getByRole('link', { name: '1 active grant' })).toBe(active)
    expect(active).toHaveAttribute('href', '/access')
  })

  it('links pending machines and host-name changes to Machines as actionable attention', async () => {
    signedIn({
      'GET /api/v1/machines': {
        body: {
          items: [
            machine(),
            machine({ fingerprint: 'ff'.repeat(32), display: 'ffff', status: 'trusted', hostName: 'old-host', pendingHostName: 'new-host', actions: ['approve-host-change'] }),
          ],
        },
      },
    })
    renderApp('/')

    const pending = await screen.findByRole('link', { name: '1 machine is waiting for approval' })
    const changed = await screen.findByRole('link', { name: '1 machine reported a new host name' })
    const attention = screen.getByRole('heading', { name: 'Needs your attention' }).closest('section') as HTMLElement
    expect(within(attention).getByRole('link', { name: '1 machine is waiting for approval' })).toBe(pending)
    expect(within(attention).getByRole('link', { name: '1 machine reported a new host name' })).toBe(changed)
    expect(pending).toHaveAttribute('href', '/machines')
    expect(changed).toHaveAttribute('href', '/machines')
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

  it('retries each optional query locally and shows its data once it succeeds', async () => {
    const user = userEvent.setup()
    let machinesFail = true
    let grantsFail = true
    signedIn({
      'GET /api/v1/machines': () => {
        if (!machinesFail) return { body: { items: [machine()] } }
        machinesFail = false

        return problem(400, 'machines-unavailable', 'machines are unavailable')
      },
      'GET /api/v1/grants': () => {
        if (!grantsFail) return { body: { items: [grant()] } }
        grantsFail = false

        return problem(400, 'grants-unavailable', 'grants are unavailable')
      },
    })
    renderApp('/')

    await screen.findByText(/Machine attention could not be loaded/)
    await screen.findByText(/Active grants could not be loaded/)
    await user.click(screen.getByRole('button', { name: /try again loading machine attention/i }))
    expect(await screen.findByRole('link', { name: '1 machine is waiting for approval' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /try again loading active grants/i }))
    expect(await screen.findByRole('link', { name: '1 active grant' })).toBeInTheDocument()
  })
})

describe('machine polling', () => {
  it('announces a newly paired machine without taking focus from the current task', async () => {
    let paired = false
    signedIn({
      'GET /api/v1/machines': () => ({
        body: {
          items: [
            machine({ status: 'trusted', actions: ['rename'] }),
            ...(paired ? [machine({ fingerprint: 'ff'.repeat(32), display: 'ffff', hostName: 'late-host' })] : []),
          ],
        },
      }),
    })
    renderApp('/machines')
    const add = await screen.findByRole('button', { name: 'Add a machine' })
    add.focus()
    paired = true

    expect(await screen.findByText(/A machine paired: late-host/, {}, { timeout: 4000 })).toBeInTheDocument()
    expect(add).toHaveFocus()
  })
})

describe('sign-in', () => {
  it('signs in with one passkey tap and returns to the metadata view', async () => {
    const user = userEvent.setup()
    let tapped = false
    let started = false
    let claimed = false
    setBrowserSecret(null)
    const fake = installFakeApi({
      'GET /api/v1/status': { body: status() },
      'GET /api/v1/session': () => ({ body: claimed ? session() : tapped ? { ...signedOut(), login: { state: 'ready', problem: null } } : started ? { ...signedOut(), login: { state: 'waiting', problem: null } } : signedOut() }),
      'POST /api/v1/browser': { status: 201, body: { antiForgery: 'browser-secret-1' } },
      'POST /api/v1/session/inline': () => {
        started = true

        return { status: 201, body: { proof: { mode: 'webauthn', payload: JSON.stringify({ bind: 'AQ', rpId: 'localhost', timeout: 60000 }) } } }
      },
      'POST /api/v1/session/inline/proof': () => { tapped = true; return { body: { ok: true } } },
      'POST /api/v1/session/claim': () => {
        claimed = true

        return { status: 201, body: { antiForgery: 'session-secret-1', session: session() } }
      },
      'GET /api/v1/machines': { body: { items: [machine({ status: 'trusted', actions: ['rename'] })] } },
      'GET /api/v1/grants': { body: { items: [] } },
    })
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => ({ rawId: new Uint8Array([1]).buffer, response: { authenticatorData: new Uint8Array([2]).buffer, clientDataJSON: new Uint8Array([3]).buffer, signature: new Uint8Array([4]).buffer } })) } })
    renderApp('/machines')
    expect(await screen.findByRole('button', { name: /build-host.*View machine/ })).toBeVisible()
    await user.click(await screen.findByRole('link', { name: 'Sign in' }))
    await user.click(await screen.findByRole('button', { name: 'Sign in with passkey' }))
    expect(vi.mocked(navigator.credentials.get)).toHaveBeenCalledTimes(1)
    expect(fake.calls.find((call) => call.method === 'POST' && call.path === '/api/v1/session/inline')?.headers['X-Admin-Token']).toBe('browser-secret-1')

    expect(await screen.findByRole('heading', { level: 1, name: 'Machines' }, { timeout: 4000 })).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: /build-host.*View machine/ })).toBeInTheDocument()
    // The claim is a POST made by the page (the read of the session claims nothing), and from then on every request carries the session's own secret.
    expect(fake.calls.some((call) => call.method === 'POST' && call.path === '/api/v1/session/claim')).toBe(true)
    await waitFor(() => expect(fake.calls.some((call) => call.path === '/api/v1/machines' && call.headers['X-Admin-Token'] === 'session-secret-1')).toBe(true))
  })

  it('is not signed in by a click made before the sign-in is prepared: until then nothing is named like the sign-in button', async () => {
    setBrowserSecret(null)
    installFakeApi({
      'GET /api/v1/status': { body: status() },
      'GET /api/v1/session': { body: signedOut() },
      'POST /api/v1/browser': { status: 201, body: { antiForgery: 'browser-secret-1' } },
      'POST /api/v1/session/inline': { status: 201, body: { proof: { mode: 'webauthn', payload: JSON.stringify({ bind: 'AQ', rpId: 'localhost', timeout: 60000 }) } } },
    })
    // The service's status is slow (a loaded machine): the page is waiting for it.
    const prepared = globalThis.fetch
    let release: () => void = () => undefined
    const slow = new Promise<void>((resolve) => { release = resolve })
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/api/v1/status')) await slow

      return prepared(input, init)
    })
    renderApp('/sign-in')

    const waiting = await screen.findByRole('button', { name: /Preparing/ })
    expect(waiting).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Sign in with passkey' })).not.toBeInTheDocument()
    release()
    // Once prepared, the button with that name is the real one.
    expect(await screen.findByRole('button', { name: 'Sign in with passkey' })).toBeEnabled()
  })

  it('shows a service refusal when sign-in cannot be prepared', async () => {
    const user = userEvent.setup()
    installFakeApi({
      'GET /api/v1/status': { body: status() },
      'GET /api/v1/session': { body: signedOut() },
      'POST /api/v1/browser': { status: 201, body: { antiForgery: 'browser-secret-1' } },
      'POST /api/v1/session/inline': problem(409, 'proof-unavailable', 'no admin passkey is available'),
    })
    renderApp('/sign-in')
    await user.click(await screen.findByRole('button', { name: /sign in with passkey/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent('no admin passkey is available')
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

    expect(await screen.findByRole('link', { name: 'Sign in' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: 'Overview' })).toBeInTheDocument()
    expect(fake.calls.find((call) => call.method === 'DELETE')?.headers['X-Admin-Token']).toBe('session-secret-1')
  })

  it('offers sign-in without closing the current page when the session ends', async () => {
    let ended = false
    signedIn({
      'GET /api/v1/session': () => ({ body: ended ? signedOut() : session() }),
      'GET /api/v1/machines': () => {
        ended = true

        return problem(401, 'session-required', 'this needs an administrator session')
      },
    })
    renderApp('/machines')

    expect(await screen.findByRole('link', { name: 'Sign in' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: 'Machines' })).toBeInTheDocument()
  })
})

describe('authenticator app resume', () => {
  it('lets a locked admin session select an app and enter a code without prompting for a passkey', async () => {
    const user = userEvent.setup()
    let locked = true
    const fake = signedIn({
      'GET /api/v1/session': () => ({ body: session({ editingLocked: locked }) }),
      'GET /api/v1/access-credentials/authenticators': { body: { items: [{ id: 'phone', name: 'Phone' }, { id: 'backup', name: 'Backup' }] } },
      'POST /api/v1/session/resume/authenticator': () => {
        locked = false
        return { body: { ok: true } }
      },
    })
    renderApp('/')
    await waitFor(() => expect(fake.count('GET /api/v1/access-credentials/authenticators')).toBe(1))
    await user.click(await screen.findByRole('button', { name: 'Resume editing' }))
    const dialog = within(await screen.findByRole('dialog', { name: 'Resume editing' }))
    await user.selectOptions(dialog.getByRole('combobox', { name: 'Authenticator app' }), 'backup')
    await user.type(dialog.getByRole('textbox', { name: /Six-digit code/ }), '012345')
    await user.click(dialog.getByRole('button', { name: 'Resume editing' }))
    expect(await screen.findByRole('button', { name: 'Lock editing' })).toBeInTheDocument()
    expect(fake.calls.find(call => call.path === '/api/v1/session/resume/authenticator')?.body).toEqual({ id: 'backup', code: '012345' })
    expect(fake.count('POST /api/v1/authorizations/inline')).toBe(0)
  })
})

describe('the locked authority', () => {
  it('can be unlocked without a session, with its own authorization', async () => {
    const openSpy = vi.spyOn(window, 'open').mockReturnValue(null)
    const user = userEvent.setup()
    let proved = false
    const fake = installFakeApi({
      'GET /api/v1/status': { body: status({ locked: true }) },
      'GET /api/v1/session': { body: signedOut() },
      'POST /api/v1/authorizations/inline': { status: 201, body: authorization({ operation: 'unlock', link: null, proof: { mode: 'webauthn', payload: JSON.stringify({ bind: 'AQ', rpId: 'localhost', timeout: 60000 }) }, parameters: [], sentence: 'Unlock the authority.' }) },
      'POST /api/v1/authorizations/auth-id-0001/proof': () => { proved = true; return { body: { ok: true } } },
      'GET /api/v1/authorizations/auth-id-0001': () => ({ body: authorization({ operation: 'unlock', state: proved ? 'consumed' : 'pending', parameters: [], result: proved ? { outcome: 'applied', code: null, detail: null, link: null, invitation: null, invitationGone: false } : null }) }),
    })
    renderApp('/')
    await user.click(await screen.findByRole('button', { name: 'Unlock the authority' }))
    const dialog = await screen.findByRole('dialog')
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => ({ rawId: new Uint8Array([1]).buffer, response: { authenticatorData: new Uint8Array([2]).buffer, clientDataJSON: new Uint8Array([3]).buffer, signature: new Uint8Array([4]).buffer } })) } })
    await user.click(await within(dialog).findByRole('button', { name: 'Unlock' }))

    // One step; the service makes the change at the tap, and this page only reads the result (no unlock call of its own).
    expect(await screen.findByText('The authority is unlocked.')).toBeInTheDocument()
    expect(fake.count('POST /api/v1/unlock')).toBe(0)
    expect(fake.calls.find((call) => call.path === '/api/v1/authorizations/inline')?.body).toEqual({ operation: 'unlock', parameters: {} })
    expect(openSpy).not.toHaveBeenCalled()
  })
})

describe('audit search', () => {
  it('puts the search in the address and asks the service with the filters', async () => {
    const user = userEvent.setup()
    const fake = signedIn()
    renderApp('/audit')
    await user.type(await screen.findByLabelText(/contains text/i), 'deploy.cmd')
    await user.click(screen.getByText('More filters'))
    await user.selectOptions(screen.getByLabelText('Time range'), 'day')
    await user.selectOptions(screen.getByLabelText(/kind of event/i), 'launch')
    await user.click(screen.getByRole('button', { name: 'Search' }))

    await waitFor(() => {
      const last = fake.calls.filter((call) => call.path === '/api/v1/audit/events').at(-1)
      expect(last?.query.get('text')).toBe('deploy.cmd')
      expect(last?.query.get('type')).toBe('launch')
      expect(Date.parse(last?.query.get('until') ?? '') - Date.parse(last?.query.get('since') ?? '')).toBe(24 * 60 * 60 * 1000)
    })
    expect(await screen.findByText('No events match these filters.')).toBeInTheDocument()
    expect(screen.getByLabelText(/maximum results/i)).toBeInTheDocument()
    expect(screen.getByText('Defaults to 100. Increase the limit to see more history.')).toBeInTheDocument()
  })
})

describe('audit result counts', () => {
  const cases = [
    {
      what: 'events',
      route: '/audit',
      api: 'GET /api/v1/audit/events',
      item: (n: number) => ({
        eventId: 'event-' + n,
        sequence: n,
        time: '2026-11-09T10:00:00Z',
        received: '2026-11-09T10:00:01Z',
        machine: machine().fingerprint,
        type: 'launch',
        outcome: 'started',
        reason: '',
        requestId: 'request-' + n,
        folder: '',
        program: '',
        arguments: [],
        grantId: '',
        exitCode: null,
        metadata: {},
      }),
      one: '1 event found.',
      many: 'Showing 2 events.',
    },
    {
      what: 'changes',
      route: '/audit/changes',
      api: 'GET /api/v1/audit/changes',
      item: (n: number) => ({ id: n, time: '2026-11-09T10:00:00Z', event: 'machine-approve', machine: machine().fingerprint, actor: 'admin passkey', detail: 'approved' }),
      one: '1 change found.',
      many: 'Showing 2 changes.',
    },
    {
      what: 'gaps',
      route: '/audit/gaps',
      api: 'GET /api/v1/audit/gaps',
      item: (n: number) => ({ id: n, machine: machine().fingerprint, kind: 'missing', from: n, to: n + 1, detected: '2026-11-09T10:00:00Z', resolved: null, epoch: 'e' }),
      one: '1 gap found.',
      many: 'Showing 2 gaps.',
    },
  ]

  it.each(cases)('uses singular wording for one $what result', async ({ route, api, item, one }) => {
    signedIn({ [api]: { body: { items: [item(1)] } } })
    renderApp(route)
    expect(await screen.findByText(one)).toBeInTheDocument()
  })

  it.each(cases)('uses plural wording for two $what results', async ({ route, api, item, many }) => {
    signedIn({ [api]: { body: { items: [item(1), item(2)] } } })
    renderApp(route)
    expect(await screen.findByText(many)).toBeInTheDocument()
  })
})

describe('settings and passkey context', () => {
  afterEach(() => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined })
  })

  it('summarizes authority behavior in the four settings groups', async () => {
    signedIn()
    renderApp('/settings')

    for (const name of ['Review access', 'Audit retention', 'Administrator sessions', 'Authority signing key']) {
      expect(await screen.findByRole('heading', { level: 2, name })).toBeInTheDocument()
    }
    expect(screen.getByText('15 minutes')).toBeInTheDocument()
    expect(screen.getByText('480 minutes, however busy')).toBeInTheDocument()
  })

  it('shows whether review text is open or locked', async () => {
    signedIn({ 'GET /api/v1/status': { body: status({ reviewOpen: true }) } })
    renderApp('/settings')

    expect(await screen.findByText('Review text')).toBeInTheDocument()
    expect(await screen.findByText('open')).toBeInTheDocument()
  })

  it('keeps zero audit retention visible as no limit in the page and the edit form', async () => {
    const user = userEvent.setup()
    signedIn({ 'GET /api/v1/settings': { body: settings({ auditRetentionDays: 0 }) } })
    renderApp('/settings')

    expect(await screen.findByText('Forever')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Change audit retention...' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('textbox', { name: /Days to keep audit events/ })).toHaveValue('0')
    expect(within(dialog).getByText('0 keeps everything.')).toBeInTheDocument()
  })

  it('copies the complete public authority fingerprint and announces the result', async () => {
    const user = userEvent.setup()
    const writeText = vi.fn(async () => undefined)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    const full = 'AB12 '.repeat(15) + 'CD34'
    signedIn({ 'GET /api/v1/settings': { body: settings({ authorityKey: full }) } })
    renderApp('/settings')

    expect(await screen.findByText(full)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Copy fingerprint' }))

    expect(writeText).toHaveBeenCalledWith(full)
    expect(screen.getByText('Copied.')).toHaveAttribute('role', 'status')
  })

  it('keeps the complete authority fingerprint readable when copying is not possible', async () => {
    const user = userEvent.setup()
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn(async () => { throw new Error('copy refused') }) },
    })
    const full = 'AB12 '.repeat(15) + 'CD34'
    signedIn({ 'GET /api/v1/settings': { body: settings({ authorityKey: full }) } })
    renderApp('/settings')

    expect(await screen.findByText(full)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Copy fingerprint' }))

    expect(await screen.findByText('Copying was not possible here; select the fingerprint and copy it.')).toBeInTheDocument()
    expect(screen.getByText(full)).toBeInTheDocument()
  })

  it('explains credential role separately from credential kind on the passkeys page', async () => {
    signedIn()
    renderApp('/passkeys')

    await userEvent.setup().click(await screen.findByRole('button', { name: 'admin key View passkey' }))
    expect(within(screen.getByRole('dialog')).getByText(/Admin passkeys can approve runs/)).toBeInTheDocument()
  })

  it('keeps each passkey name, role, kind and creation time readable', async () => {
    const longName = 'workstation-admin-' + 'x'.repeat(70)
    const created = '2026-11-01T10:00:00Z'
    signedIn({
      'GET /api/v1/passkeys': {
        body: {
          available: true,
          problem: null,
          items: [
            { name: longName, detail: 'security key', created, admin: true },
            { name: 'deploy approval', detail: 'platform passkey', created, admin: false },
          ],
        },
      },
    })
    renderApp('/passkeys')

    const user = userEvent.setup()
    const adminButton = await screen.findByRole('button', { name: longName + ' View passkey' })
    const admin = adminButton.closest('tr') as HTMLElement
    expect(within(admin).getByText('Admin')).toBeInTheDocument()
    expect(admin.querySelector('time')).toHaveAttribute('datetime', created)
    await user.click(adminButton)
    expect(within(screen.getByRole('dialog')).getByText('security key')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Close' }))

    const approvalButton = screen.getByRole('button', { name: 'deploy approval View passkey' })
    expect(within(approvalButton.closest('tr') as HTMLElement).getByText('Approval')).toBeInTheDocument()
    await user.click(approvalButton)
    expect(within(screen.getByRole('dialog')).getByText('platform passkey')).toBeInTheDocument()
  })

  it('explains the delegated enrollment sequence before Add and in its review', async () => {
    const user = userEvent.setup()
    signedIn()
    renderApp('/passkeys')

    await user.click(await screen.findByRole('button', { name: 'Add passkey' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Tap your passkey on each page that opens.')).toBeInTheDocument()
    expect(within(dialog).getByText('Add a passkey: the enrollment pages follow, each with its own passkey tap.')).toBeInTheDocument()
  })

  it('keeps Remove attached to the exact passkey and reviews its name and kind', async () => {
    const user = userEvent.setup()
    signedIn({
      'GET /api/v1/passkeys': {
        body: { available: true, problem: null, items: [{ name: 'old key', detail: 'security key', created: '2026-11-01T10:00:00Z', admin: false }] },
      },
    })
    renderApp('/passkeys')

    await user.click(await screen.findByRole('button', { name: 'old key View passkey' }))
    await user.click(within(screen.getByRole('dialog', { name: 'old key' })).getByRole('button', { name: 'Remove passkey' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('Passkey').parentElement).toHaveTextContent('old key')
    expect(within(dialog).getByText('Kind').parentElement).toHaveTextContent('security key')
    expect(within(dialog).getByText('The last admin passkey cannot be removed.')).toBeInTheDocument()
    expect(within(dialog).getByText('Remove the passkey "old key".')).toBeInTheDocument()
  })

  it('never presents unavailable passkey storage as an empty list', async () => {
    signedIn({
      'GET /api/v1/passkeys': { body: { available: false, problem: 'The passkey store could not be read.', items: [] } },
    })
    renderApp('/passkeys')

    expect(await screen.findByText('Passkeys are not available')).toBeInTheDocument()
    expect(screen.getByText('The passkey store could not be read.')).toBeInTheDocument()
    expect(screen.queryByText('No passkey is enrolled.')).toBeNull()
    expect(screen.queryByRole('table', { name: 'Enrolled passkeys' })).toBeNull()
  })

  it('shows an empty store only when passkey storage is available', async () => {
    signedIn({ 'GET /api/v1/passkeys': { body: { available: true, problem: null, items: [] } } })
    renderApp('/passkeys')

    expect(await screen.findByText('No passkey is enrolled.')).toBeInTheDocument()
    expect(screen.queryByText('Passkeys are not available')).toBeNull()
  })

  it('keeps a failure to list passkeys separate from an empty store', async () => {
    signedIn({ 'GET /api/v1/passkeys': problem(503, 'passkeys-unavailable', 'the passkey store is unavailable') })
    renderApp('/passkeys')

    expect(await screen.findByText('The passkeys could not be listed', {}, { timeout: 4000 })).toBeInTheDocument()
    expect(screen.queryByText('No passkey is enrolled.')).toBeNull()
    expect(screen.queryByText('Passkeys are not available')).toBeNull()
  })
})

describe('grant and audit navigation', () => {
  it('links a grant to its host events and machine authority changes', async () => {
    const user = userEvent.setup()
    signedIn({ 'GET /api/v1/grants': { body: { items: [grant()] } } })
    renderApp('/access')

    await user.click(await screen.findByRole('button', { name: /View grant grant-0001/ }))
    expect(await screen.findByRole('link', { name: 'Events for this grant' })).toHaveAttribute('href', '/audit?grant=grant-0001')
    expect(screen.getByRole('link', { name: 'Changes to this machine' })).toHaveAttribute(
      'href',
      '/audit/changes?machine=' + grant().fingerprint,
    )
  })

  it('links audit records to filtered evidence and labels both event timestamps', async () => {
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

    await userEvent.setup().click(await screen.findByRole('button', { name: /View .* event/ }))
    expect(await screen.findByRole('link', { name: machine().fingerprint })).toHaveAttribute(
      'href',
      '/audit?machine=' + machine().fingerprint,
    )
    expect(screen.getByRole('link', { name: 'grant-0001' })).toHaveAttribute('href', '/audit?grant=grant-0001')
    const occurred = screen.getByText('Occurred').parentElement as HTMLElement
    const received = screen.getByText('Received').parentElement as HTMLElement
    expect(occurred.querySelector('time')).toHaveAttribute('datetime', '2026-11-09T10:00:00Z')
    expect(received.querySelector('time')).toHaveAttribute('datetime', '2026-11-09T10:00:03Z')
    expect(screen.queryByText('Received by authority')).toBeNull()
  })

  it('shows the grant approval, last change and unlock passkeys on a host event', async () => {
    signedIn({
      'GET /api/v1/audit/events': {
        body: { items: [{
          eventId: 'e1', sequence: 1, time: '2026-11-09T10:00:00Z', received: '2026-11-09T10:00:01Z', machine: 'ab12',
          type: 'launch', outcome: 'started', reason: '', requestId: 'r1', folder: '', program: '', arguments: [], grantId: 'grant-0001', exitCode: null,
          metadata: {
            grantApprovedId: 'phone001long', grantApprovedName: 'phone', grantApprovedAdmin: 'false',
            grantChangedId: 'phone002long', grantChangedName: 'phone', grantChangedAdmin: 'false',
            unlockId: 'laptop01long', unlockName: 'laptop', unlockAdmin: 'true',
          },
        }] },
      },
    })
    renderApp('/audit')

    await userEvent.setup().click(await screen.findByRole('button', { name: /View started event/ }))
    const approved = await screen.findByText('Grant approved by')
    expect(approved.parentElement).toHaveTextContent('phone (approval, phone001)')
    expect(screen.getByText('Grant changed by').parentElement).toHaveTextContent('phone (approval, phone002)')
    expect(screen.getByText('Authority unlocked by').parentElement).toHaveTextContent('laptop (admin, laptop01)')
    expect(screen.getByTitle('phone001long')).toBeInTheDocument()
    expect(screen.queryByText('Metadata: grantApprovedId')).toBeNull()
  })

  it('labels the session passkey for a sign-out in authority history', async () => {
    signedIn({
      'GET /api/v1/audit/changes': {
        body: { items: [{
          id: 1, time: '2026-11-09T10:00:00Z', event: 'admin-session', machine: null, actor: 'phone', detail: 'signed out',
          metadata: { sessionKeyId: 'phone001long', sessionKeyName: 'phone', sessionKeyAdmin: 'false' },
        }] },
      },
    })
    renderApp('/audit/changes')

    await userEvent.setup().click(await screen.findByRole('button', { name: /View change/ }))
    const role = await screen.findByText('Session passkey')
    expect(role.parentElement).toHaveTextContent('phone (approval, phone001)')
    expect(screen.queryByText('Passkey used')).toBeNull()
  })

  it('links an authority change machine to the machine-filtered authority changes view', async () => {
    signedIn({
      'GET /api/v1/audit/changes': {
        body: { items: [{ id: 1, time: '2026-11-09T10:00:00Z', event: 'machine-approve', machine: machine().fingerprint, actor: 'admin passkey', detail: 'approved' }] },
      },
    })
    renderApp('/audit/changes')

    await userEvent.setup().click(await screen.findByRole('button', { name: /View change/ }))
    expect(await screen.findByRole('link', { name: machine().fingerprint })).toHaveAttribute(
      'href',
      '/audit/changes?machine=' + machine().fingerprint,
    )
  })

  it('links a numbering gap machine to the machine-filtered gaps view', async () => {
    signedIn({
      'GET /api/v1/audit/gaps': {
        body: { items: [{ id: 1, machine: machine().fingerprint, kind: 'missing', from: 3, to: 4, detected: '2026-11-09T10:00:00Z', resolved: null, epoch: 'e' }] },
      },
    })
    renderApp('/audit/gaps')

    await userEvent.setup().click(await screen.findByRole('button', { name: /View gap/ }))
    expect(await screen.findByRole('link', { name: machine().fingerprint })).toHaveAttribute(
      'href',
      '/audit/gaps?machine=' + machine().fingerprint,
    )
  })

  it('can clear URL-backed audit filters', async () => {
    const user = userEvent.setup()
    signedIn()
    renderApp('/audit?text=deploy.cmd&machine=' + machine().fingerprint)

    expect(await screen.findByLabelText(/contains text/i)).toHaveValue('deploy.cmd')
    expect(screen.getByLabelText(/machine \(fingerprint/i)).toHaveValue(machine().fingerprint)
    await user.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(screen.getByLabelText(/contains text/i)).toHaveValue('')
    expect(screen.getByLabelText(/machine \(fingerprint/i)).toHaveValue('')
    expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull()
  })
})

describe('what is shown', () => {
  it('lists machines with the actions each one offers', async () => {
    const user = userEvent.setup()
    signedIn({ 'GET /api/v1/machines': { body: { items: [machine(), machine({ fingerprint: 'ff'.repeat(32), display: 'ffff', status: 'trusted', friendlyName: 'ci box', actions: ['disable', 'untrust', 'rename'] })] } } })
    renderApp('/machines')
    await user.click(await screen.findByRole('button', { name: /ci box.*View machine/ }))
    const card = await screen.findByRole('dialog', { name: 'ci box' })
    expect(within(card).getByText('build-host')).toBeInTheDocument()
    expect(within(card).getByText('ffff')).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: /^disable/i })).toBeInTheDocument()
    await user.click(within(card).getByRole('button', { name: 'Close' }))
    await user.click(screen.getByRole('button', { name: /build-host.*View machine/ }))
    expect(within(await screen.findByRole('dialog', { name: 'build-host' })).getByRole('button', { name: /^approve/i })).toBeInTheDocument()
  })

  it('warns on a machine whose identity may have been copied, never by itself disabling it', async () => {
    const user = userEvent.setup()
    signedIn({
      'GET /api/v1/machines': {
        body: { items: [machine({ status: 'trusted', actions: ['disable', 'rename'], copyWarning: { count: 3, firstAddress: '10.0.0.5', lastAddress: '10.0.0.9', firstSeen: '2026-11-09T10:00:00Z', lastSeen: '2026-11-09T10:04:00Z' } }), machine({ fingerprint: 'ff'.repeat(32), display: 'ffff', hostName: 'clean-host', status: 'trusted', actions: ['disable'] })] },
      },
    })
    renderApp('/machines')
    const table = within(await screen.findByRole('table', { name: 'Machines' }))
    expect(table.getAllByText('Identity warning')).toHaveLength(1)
    expect(table.getAllByText('trusted')).toHaveLength(2)
    await user.click(table.getByRole('button', { name: /build-host.*View machine/ }))
    const details = within(await screen.findByRole('dialog', { name: 'build-host' }))
    expect(details.getByText(/Disable this machine if you did not start both./)).toBeInTheDocument()
    expect(details.getByText(/10.0.0.9/)).toBeInTheDocument()
    expect(details.getByRole('button', { name: /^disable/i })).toBeInTheDocument()
  })

  it('states the status in words as well as colour', async () => {
    signedIn({ 'GET /api/v1/status': { body: status({ locked: true }) } })
    renderApp('/')

    expect(await screen.findByText('Authority locked')).toBeInTheDocument()
  })
})
