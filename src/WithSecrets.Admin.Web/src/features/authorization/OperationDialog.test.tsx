import { cleanup, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { pendingAuthorization, setPendingAuthorization } from '../../api/client'
import { authorization, machine, problem, signedIn, status, violations } from '../../test/fakeApi'
import { renderApp } from '../../test/render'

const applied = { outcome: 'applied' as const, code: null, detail: null, link: null, invitation: null, invitationGone: false }
const LINK = 'http://localhost:54321/passkey-page-token'
const getPath = 'GET /api/v1/authorizations/auth-id-0001'
const deletePath = 'DELETE /api/v1/authorizations/auth-id-0001'
const approvePath = 'POST /api/v1/machines/' + machine().fingerprint + '/approve'

let opened: ReturnType<typeof vi.spyOn>
beforeEach(() => {
  opened = vi.spyOn(window, 'open').mockReturnValue(null)
})
afterEach(() => {
  opened.mockRestore()
})

type Options = {
  pendingPolls?: number
  settled?: Partial<ReturnType<typeof authorization>>
  created?: Partial<ReturnType<typeof authorization>>
  createReply?: ReturnType<typeof problem>
}

/** The machines view with one pending machine; the service creates an authorization, the tap is made elsewhere, and after `pendingPolls` looks the service reports what the tap came to. */
function setup(options: Options = {}) {
  let looks = 0

  return signedIn({
    'GET /api/v1/pairing/invitations': { body: { items: [] } },
    'POST /api/v1/authorizations':
      options.createReply ?? {
        status: 201,
        body: authorization({ parameters: [{ name: 'fingerprint', value: machine().fingerprint }, { name: 'name', value: 'build-host' }], ...options.created }),
      },
    [getPath]: () => {
      looks++
      const settled = looks > (options.pendingPolls ?? 1)

      return { body: authorization({ state: settled ? 'consumed' : 'pending', result: settled ? applied : null, ...(settled ? options.settled : {}) }) }
    },
    [deletePath]: { body: { ok: true } },
  })
}

async function openApprove(user: ReturnType<typeof userEvent.setup>) {
  renderApp('/machines')
  await user.click(await screen.findByRole('button', { name: /^approve/i }))

  return screen.findByRole('dialog')
}

describe('an administrative change', () => {
  it('is one step: Continue opens the passkey page, and the service makes the change at the tap (this page only reads the outcome)', async () => {
    const user = userEvent.setup()
    const fake = setup()
    const dialog = await openApprove(user)
    // The name starts as the host name.
    expect(within(dialog).getByLabelText(/friendly name/i)).toHaveValue('build-host')
    expect(within(dialog).queryByRole('button', { name: 'Review' })).toBeNull()
    expect(fake.count('POST /api/v1/authorizations')).toBe(0)
    expect(await violations(dialog)).toEqual([])

    await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))

    // Review, ask and open are one click: the passkey page was opened (own tab, no opener) for exactly the operation and parameters asked.
    await waitFor(() => expect(opened).toHaveBeenCalledWith(LINK, '_blank', 'noopener,noreferrer'))
    expect(fake.calls.find((call) => call.path === '/api/v1/authorizations')?.body).toEqual({ operation: 'machine-approve', parameters: { fingerprint: machine().fingerprint, name: 'build-host' } })
    expect(await within(dialog).findByText('Waiting for your passkey tap')).toBeInTheDocument()
    expect(within(dialog).getByRole('link', { name: /did not open/i })).toHaveAttribute('href', LINK)

    // The tap is made on the other page; the service applies it. This page makes no mutation call.
    expect(await within(dialog).findByRole('button', { name: 'Close' })).toBeInTheDocument()
    expect(within(dialog).getByText('Done')).toBeInTheDocument()
    expect(fake.count(approvePath)).toBe(0)
    expect(fake.calls.filter((call) => call.method !== 'GET').map((call) => call.method + ' ' + call.path)).toEqual(['POST /api/v1/authorizations'])
    expect(pendingAuthorization()).toBeNull()
  })

  it('cancels the request at the service when it is cancelled before the tap', async () => {
    const user = userEvent.setup()
    const fake = setup({ pendingPolls: 1000 })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))
    await user.click(await within(dialog).findByRole('button', { name: 'Cancel the request' }))

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    await waitFor(() => expect(fake.count(deletePath)).toBe(1))
    expect(fake.count(approvePath)).toBe(0)
    expect(pendingAuthorization()).toBeNull()
  })

  it('does not report a change when the authorization is refused, and says why', async () => {
    const user = userEvent.setup()
    const fake = setup()
    fake.on(getPath, { body: authorization({ state: 'refused', detail: 'the passkey page refused it' }) })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))

    expect(await within(dialog).findByText('the passkey page refused it')).toBeInTheDocument()
    expect(within(dialog).getByRole('alert')).toHaveTextContent('The change was not made')
    expect(pendingAuthorization()).toBeNull()
  })

  it('shows a good tap whose change could not be made as not made, with the service sentence', async () => {
    const user = userEvent.setup()
    setup({ settled: { result: { outcome: 'failed' as const, code: 'operation-failed', detail: 'the machine changed since the page was opened', link: null, invitation: null, invitationGone: false } } })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))

    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('the machine changed since the page was opened')
    expect(alert).toHaveTextContent('operation-failed')
  })

  it('does not wait for the service when it authorizes something other than what was asked, and cancels that authorization', async () => {
    const user = userEvent.setup()
    const fake = setup({ created: { operation: 'machine-disable' } })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))

    expect(await within(dialog).findByText(/other than what was asked/)).toBeInTheDocument()
    expect(fake.count(getPath)).toBe(0)
    await waitFor(() => expect(fake.count(deletePath)).toBe(1))
    expect(opened).not.toHaveBeenCalled()
  })

  it('shows the service refusal as plain text and offers a fresh start (a new authorization)', async () => {
    const user = userEvent.setup()
    const fake = setup({ createReply: problem(409, 'operation-refused', 'this machine is not pending <b>x</b>') })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))

    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('this machine is not pending <b>x</b>')
    expect(alert.querySelector('b')).toBeNull()
    expect(alert).toHaveTextContent('operation-refused')
    await user.click(within(dialog).getByRole('button', { name: 'Start over' }))
    await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))
    await waitFor(() => expect(fake.count('POST /api/v1/authorizations')).toBe(2))
  })

  it('every change asks for its own authorization (nothing is reused)', async () => {
    const user = userEvent.setup()
    const fake = setup()
    for (const round of [1, 2]) {
      const dialog = await openApprove(user)
      await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))
      await user.click(await within(dialog).findByRole('button', { name: 'Close' }))
      expect(fake.count('POST /api/v1/authorizations')).toBe(round)
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
      cleanup()
    }
  })

  it('validates input and announces the error on the field', async () => {
    const user = userEvent.setup()
    setup()
    renderApp('/settings')
    await user.click(await screen.findByRole('button', { name: /change audit retention/i }))
    const dialog = await screen.findByRole('dialog')
    const days = within(dialog).getByLabelText(/days to keep/i)
    await user.clear(days)
    await user.type(days, 'abc')
    await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))

    expect(days).toHaveAttribute('aria-invalid', 'true')
    expect(within(dialog).getByRole('alert')).toHaveTextContent(/whole number/)
    expect(days.getAttribute('aria-describedby')).toContain('error')
    expect(opened).not.toHaveBeenCalled()
  })
})

describe('a tap is never lost: the page that comes back reads what the service made of it', () => {
  it('keeps only the id and the sentence of the waiting authorization in this tab, never the link or a parameter', async () => {
    const user = userEvent.setup()
    setup({ pendingPolls: 1000 })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))
    await within(dialog).findByRole('button', { name: 'Cancel the request' })

    expect(pendingAuthorization()).toMatchObject({ id: 'auth-id-0001', operation: 'machine-approve', title: 'Approve this machine' })
    const text = JSON.stringify({ ...sessionStorage })
    expect(text).not.toContain('passkey-page-token')
    expect(text).not.toContain(machine().fingerprint)
    expect(JSON.stringify({ ...localStorage })).not.toContain('auth-id-0001')
  })

  it('a reloaded tab opens on the waiting authorization and shows its result, with no mutation call', async () => {
    const fake = setup({ pendingPolls: 1 })
    setPendingAuthorization({ id: 'auth-id-0001', operation: 'machine-approve', title: 'Approve this machine', summary: 'Approve machine ab12 cd34 ef56 ab12 as "ci box".' })
    renderApp('/machines')

    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/reloaded while a passkey tap was waiting/)).toBeInTheDocument()
    expect(await within(dialog).findByRole('button', { name: 'Close' })).toBeInTheDocument()
    expect(within(dialog).getByText(/Approve machine ab12 cd34 ef56 ab12 as "ci box"\./)).toBeInTheDocument()
    expect(fake.calls.some((call) => call.method === 'POST')).toBe(false)
    expect(pendingAuthorization()).toBeNull()
  })

  it('a lock ends the session and the authorization: the page asks the authority, and says it is locked', async () => {
    const fake = setup()
    fake.on(getPath, problem(401, 'session-required', 'no session'))
    fake.on('GET /api/v1/status', { body: status({ locked: true }) })
    setPendingAuthorization({ id: 'auth-id-0001', operation: 'lock', title: 'Lock the authority', summary: 'Lock the authority now.' })
    renderApp('/machines')

    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('The authority is locked.')).toBeInTheDocument()
  })

  it('a session that ended before the result could be read says so, and where to look', async () => {
    const fake = setup()
    fake.on(getPath, problem(404, 'not-found', 'no such authorization for this caller'))
    setPendingAuthorization({ id: 'auth-id-0001', operation: 'machine-approve', title: 'Approve this machine', summary: 'x' })
    renderApp('/machines')

    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(/audit history/)
    expect(pendingAuthorization()).toBeNull()
  })
})
