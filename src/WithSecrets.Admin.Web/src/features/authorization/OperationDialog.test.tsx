import { cleanup, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { pendingAuthorization, setPendingAuthorization } from '../../api/client'
import { authorization, machine, problem, signedIn, status, violations } from '../../test/fakeApi'
import { renderApp } from '../../test/render'

const applied = { outcome: 'applied' as const, code: null, detail: null, link: null, invitation: null, invitationGone: false }
const getPath = 'GET /api/v1/authorizations/auth-id-0001'
const deletePath = 'DELETE /api/v1/authorizations/auth-id-0001'
const approvePath = 'POST /api/v1/machines/' + machine().fingerprint + '/approve'
const inlinePath = 'POST /api/v1/authorizations/inline'
const proofPath = 'POST /api/v1/authorizations/auth-id-0001/proof'

let opened: ReturnType<typeof vi.spyOn>
let credentialDescriptor: PropertyDescriptor | undefined
beforeEach(() => {
  opened = vi.spyOn(window, 'open').mockReturnValue(null)
  credentialDescriptor = Object.getOwnPropertyDescriptor(navigator, 'credentials')
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn(async () => ({ rawId: new Uint8Array([1]).buffer, response: { authenticatorData: new Uint8Array([2]).buffer, clientDataJSON: new Uint8Array([3]).buffer, signature: new Uint8Array([4]).buffer } })) } })
})
afterEach(() => {
  opened.mockRestore()
  if (credentialDescriptor) Object.defineProperty(navigator, 'credentials', credentialDescriptor)
  else Reflect.deleteProperty(navigator, 'credentials')
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
  let proved = false

  return signedIn({
    'GET /api/v1/pairing/invitations': { body: { items: [] } },
    [inlinePath]:
      options.createReply ?? {
        status: 201,
        body: authorization({ link: null, proof: { mode: 'webauthn', payload: JSON.stringify({ bind: 'AQ', rpId: 'localhost', timeout: 60000 }) }, parameters: [{ name: 'fingerprint', value: machine().fingerprint }, { name: 'name', value: 'build-host' }], ...options.created }),
      },
    [proofPath]: () => { proved = true; return { body: { ok: true } } },
    [getPath]: () => {
      looks++
      const settled = proved || looks > (options.pendingPolls ?? 100000)

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
  it('prepares the challenge, calls WebAuthn directly from Confirm this change, and waits for service confirmation', async () => {
    const user = userEvent.setup()
    const fake = setup()
    const dialog = await openApprove(user)
    // The name starts as the host name.
    expect(within(dialog).getByLabelText(/friendly name/i)).toHaveValue('build-host')
    expect(within(dialog).queryByRole('button', { name: 'Review' })).toBeNull()
    expect(fake.count(inlinePath)).toBe(0)
    expect(await violations(dialog)).toEqual([])

    await user.click(within(dialog).getByRole('button', { name: 'Prepare confirmation' }))

    // The service prepares the operation-bound challenge before the final user gesture.
    await waitFor(() => expect(opened).not.toHaveBeenCalled())
    expect(fake.calls.find((call) => call.path === '/api/v1/authorizations/inline')?.body).toEqual({ operation: 'machine-approve', parameters: { fingerprint: machine().fingerprint, name: 'build-host' } })
    expect(await within(dialog).findByText('Review before confirming')).toBeInTheDocument()
    const fetchMock = vi.mocked(fetch)
    const fetchCount = fetchMock.mock.calls.length
    await user.click(within(dialog).getByRole('button', { name: 'Confirm this change' }))
    expect(navigator.credentials.get).toHaveBeenCalledTimes(1)

    // The SPA only reports success after its proof submission and service state confirm application.
    expect(await within(dialog).findByRole('button', { name: 'Close' })).toBeInTheDocument()
    expect(within(dialog).getByText('Done')).toBeInTheDocument()
    expect(fake.count(approvePath)).toBe(0)
    expect(fake.calls.filter((call) => call.method !== 'GET').map((call) => call.method + ' ' + call.path)).toEqual([inlinePath, proofPath])
    const fetchCalls = fetchMock.mock.calls.map(([input]) => String(input))
    const proofFetch = fetchCalls.findIndex((input, index) => index >= fetchCount && input.includes('/authorizations/auth-id-0001/proof'))
    expect(proofFetch).toBeGreaterThanOrEqual(0)
    expect(vi.mocked(navigator.credentials.get).mock.invocationCallOrder[0]).toBeLessThan(fetchMock.mock.invocationCallOrder[proofFetch]!)
    expect(pendingAuthorization()).toBeNull()
  })

  it('cancels the request at the service when it is cancelled before the tap', async () => {
    const user = userEvent.setup()
    const fake = setup({ pendingPolls: 1000 })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Prepare confirmation' }))
    await within(dialog).findByRole('button', { name: 'Confirm this change' })
    await user.click(await within(dialog).findByRole('button', { name: 'Cancel the request' }))

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    await waitFor(() => expect(fake.count(deletePath)).toBe(1))
    expect(fake.count(approvePath)).toBe(0)
    expect(pendingAuthorization()).toBeNull()
  })

  it('cancels a pending service authorization when the native passkey prompt is cancelled', async () => {
    const user = userEvent.setup()
    const fake = setup({ pendingPolls: 1000 })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Prepare confirmation' }))
    await within(dialog).findByRole('button', { name: 'Confirm this change' })
    vi.mocked(navigator.credentials.get).mockRejectedValueOnce(new DOMException('cancelled', 'NotAllowedError'))
    await user.click(within(dialog).getByRole('button', { name: 'Confirm this change' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('The page could not finish this.')
    expect(fake.count(proofPath)).toBe(0)
    expect(fake.count(deletePath)).toBe(1)
  })

  it('does not report a change when the authorization is refused, and says why', async () => {
    const user = userEvent.setup()
    const fake = setup()
    fake.on(getPath, { body: authorization({ state: 'refused', detail: 'the passkey page refused it' }) })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Prepare confirmation' }))
    await user.click(await within(dialog).findByRole('button', { name: 'Confirm this change' }))

    expect(await within(dialog).findByText('the passkey page refused it')).toBeInTheDocument()
    expect(within(dialog).getByRole('alert')).toHaveTextContent('The change was not made')
    expect(pendingAuthorization()).toBeNull()
  })

  it('shows a good tap whose change could not be made as not made, with the service sentence', async () => {
    const user = userEvent.setup()
    setup({ settled: { result: { outcome: 'failed' as const, code: 'operation-failed', detail: 'the machine changed since the page was opened', link: null, invitation: null, invitationGone: false } } })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Prepare confirmation' }))
    await user.click(await within(dialog).findByRole('button', { name: 'Confirm this change' }))

    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('the machine changed since the page was opened')
    expect(alert).toHaveTextContent('operation-failed')
  })

  it('does not wait for the service when it authorizes something other than what was asked, and cancels that authorization', async () => {
    const user = userEvent.setup()
    const fake = setup({ created: { operation: 'machine-disable' } })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Prepare confirmation' }))

    expect(await within(dialog).findByText(/other than what was asked/)).toBeInTheDocument()
    expect(fake.count(getPath)).toBe(0)
    await waitFor(() => expect(fake.count(deletePath)).toBe(1))
    expect(opened).not.toHaveBeenCalled()
  })

  it('shows the service refusal as plain text and offers a fresh start (a new authorization)', async () => {
    const user = userEvent.setup()
    const fake = setup({ createReply: problem(409, 'operation-refused', 'this machine is not pending <b>x</b>') })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Prepare confirmation' }))

    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('this machine is not pending <b>x</b>')
    expect(alert.querySelector('b')).toBeNull()
    expect(alert).toHaveTextContent('operation-refused')
    await user.click(within(dialog).getByRole('button', { name: 'Start over' }))
    fake.on(inlinePath, { status: 201, body: authorization({ link: null, proof: { mode: 'webauthn', payload: JSON.stringify({ bind: 'AQ', rpId: 'localhost', timeout: 60000 }) }, parameters: [{ name: 'fingerprint', value: machine().fingerprint }, { name: 'name', value: 'build-host' }] }) })
    await user.click(within(dialog).getByRole('button', { name: 'Prepare confirmation' }))
    await within(dialog).findByRole('button', { name: 'Confirm this change' })
    await waitFor(() => expect(fake.count(inlinePath)).toBe(2))
  })

  it('every change asks for its own authorization (nothing is reused)', async () => {
    const user = userEvent.setup()
    const fake = setup()
    for (const round of [1, 2]) {
      const dialog = await openApprove(user)
      await user.click(within(dialog).getByRole('button', { name: 'Prepare confirmation' }))
      await user.click(await within(dialog).findByRole('button', { name: 'Confirm this change' }))
      await user.click(await within(dialog).findByRole('button', { name: 'Close' }))
      expect(fake.count(inlinePath)).toBe(round)
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
    await user.click(within(dialog).getByRole('button', { name: 'Prepare confirmation' }))

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
    await user.click(within(dialog).getByRole('button', { name: 'Prepare confirmation' }))
    await within(dialog).findByRole('button', { name: 'Cancel the request' })

    expect(pendingAuthorization()).toMatchObject({ id: 'auth-id-0001', operation: 'machine-approve', title: 'Approve this machine' })
    const text = JSON.stringify({ ...sessionStorage })
    expect(text).not.toContain('passkey-page-token')
    expect(text).not.toContain(machine().fingerprint)
    expect(JSON.stringify({ ...localStorage })).not.toContain('auth-id-0001')
  })

  it('a reloaded tab reports that its challenge must be restarted, with no mutation call', async () => {
    const fake = setup({ pendingPolls: 1000 })
    setPendingAuthorization({ id: 'auth-id-0001', operation: 'machine-approve', title: 'Approve this machine', summary: 'Approve machine ab12 cd34 ef56 ab12 as "ci box".' })
    renderApp('/machines')

    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/This page was reloaded while the passkey request was in progress/)).toBeInTheDocument()
    expect(await within(dialog).findByRole('button', { name: 'Cancel the request' })).toBeInTheDocument()
    expect(within(dialog).getByText(/Approve machine ab12 cd34 ef56 ab12 as "ci box"\./)).toBeInTheDocument()
    expect(fake.calls.some((call) => call.method === 'POST')).toBe(false)
    expect(pendingAuthorization()?.id).toBe('auth-id-0001')
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
