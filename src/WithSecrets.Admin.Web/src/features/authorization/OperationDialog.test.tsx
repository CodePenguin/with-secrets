import { fireEvent, screen, waitFor, within } from '@testing-library/react'
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
  /** How many proof requests are answered with a lost connection (the service may or may not have received them). */
  lostProofReplies?: number
  /** False when a proof request whose answer is lost never reached the service. */
  lostProofReached?: boolean
}

type ServiceState = { looks: number; proofs: number; accepted: number; applied: number; proved: boolean }

/** The machines view with one pending machine; the service creates an authorization, the tap is made elsewhere, and after `pendingPolls` looks the service reports what the tap came to. */
function setup(options: Options = {}) {
  const service: ServiceState = { looks: 0, proofs: 0, accepted: 0, applied: 0, proved: false }
  const failedOperation = options.settled?.result?.outcome === 'failed'
  const acceptProof = () => {
    service.accepted++
    service.proved = true
    if (!failedOperation) service.applied++
  }

  const fake = signedIn({
    'GET /api/v1/pairing/invitations': { body: { items: [] } },
    [inlinePath]:
      options.createReply ?? {
        status: 201,
        body: authorization({ link: null, proof: { mode: 'webauthn', payload: JSON.stringify({ bind: 'AQ', rpId: 'localhost', timeout: 60000 }) }, parameters: [{ name: 'fingerprint', value: machine().fingerprint }, { name: 'name', value: 'build-host' }], ...options.created }),
      },
    [proofPath]: () => {
      service.proofs++
      if (service.proofs <= (options.lostProofReplies ?? 0)) {
        if (options.lostProofReached !== false) acceptProof()
        throw new TypeError('the answer was lost')
      }
      acceptProof()

      return { body: { ok: true } }
    },
    [getPath]: () => {
      service.looks++
      const settled = service.proved || service.looks > (options.pendingPolls ?? 100000)

      return { body: authorization({ state: settled ? 'consumed' : 'pending', result: settled ? applied : null, ...(settled ? options.settled : {}) }) }
    },
    [deletePath]: { body: { ok: true } },
  })

  return Object.assign(fake, { service })
}

async function openApprove(user: ReturnType<typeof userEvent.setup>) {
  renderApp('/machines')
  await user.click(await screen.findByRole('button', { name: /^approve/i }))

  return screen.findByRole('dialog')
}

describe('an administrative change', () => {
  it('prepares the challenge as the dialog opens, calls WebAuthn directly from the confirm button, and waits for service confirmation', async () => {
    const user = userEvent.setup()
    const fake = setup()
    const dialog = await openApprove(user)
    // The name starts as the host name and the service is asked for its challenge without another click.
    expect(await within(dialog).findByRole('button', { name: 'Approve machine' })).toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: 'Prepare confirmation' })).toBeNull()
    expect(fake.count(inlinePath)).toBe(1)
    expect(within(dialog).getByRole('button', { name: 'Change details' })).toBeInTheDocument()
    expect(await violations(dialog)).toEqual([])

    // Asking for a challenge is not a passkey prompt: nothing started the browser prompt yet.
    expect(navigator.credentials.get).not.toHaveBeenCalled()
    expect(opened).not.toHaveBeenCalled()
    expect(fake.calls.find((call) => call.path === '/api/v1/authorizations/inline')?.body).toEqual({ operation: 'machine-approve', parameters: { fingerprint: machine().fingerprint, name: 'build-host' } })
    const fetchMock = vi.mocked(fetch)
    const fetchCount = fetchMock.mock.calls.length
    await user.click(within(dialog).getByRole('button', { name: 'Approve machine' }))
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

  it('shows the service result after the proof answer is lost, and applies the change exactly once', async () => {
    const user = userEvent.setup()
    const fake = setup({ lostProofReplies: 1, lostProofReached: true })
    const dialog = await openApprove(user)
    await user.click(await within(dialog).findByRole('button', { name: 'Approve machine' }))

    // The lost answer is not a failure: the SPA keeps reading the authorization the service applied.
    expect(await within(dialog).findByText('Done')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Close' })).toBeInTheDocument()
    expect(fake.service.accepted).toBe(1)
    expect(fake.service.applied).toBe(1)
    expect(fake.service.proofs).toBe(1)
    expect(vi.mocked(navigator.credentials.get)).toHaveBeenCalledTimes(1)
    expect(fake.count(proofPath)).toBe(1)
  })

  it('does not claim success when the proof never reaches the service, and retries the same assertion safely', async () => {
    const user = userEvent.setup()
    const fake = setup({ lostProofReplies: 1, lostProofReached: false })
    const dialog = await openApprove(user)
    await user.click(await within(dialog).findByRole('button', { name: 'Approve machine' }))

    // Bounded checking hands the person a safe way out instead of waiting forever.
    expect(await within(dialog).findByText('The result is not confirmed yet')).toBeInTheDocument()
    expect(within(dialog).queryByText('Done')).toBeNull()
    expect(within(dialog).getByText(/No answer yet/)).toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: 'Approve machine' })).toBeNull()

    await user.click(within(dialog).getByRole('button', { name: 'Send the same confirmation again' }))

    expect(await within(dialog).findByText('Done')).toBeInTheDocument()
    expect(fake.service.proofs).toBe(2)
    expect(fake.service.accepted).toBe(1)
    expect(fake.service.applied).toBe(1)
    // The retry reuses the service-bound assertion: no second passkey ceremony.
    expect(vi.mocked(navigator.credentials.get)).toHaveBeenCalledTimes(1)
    expect(fake.count(deletePath)).toBe(0)
  })

  it('cancels a request whose proof never reached the service without applying anything', async () => {
    const user = userEvent.setup()
    const fake = setup({ lostProofReplies: 1, lostProofReached: false })
    const dialog = await openApprove(user)
    await user.click(await within(dialog).findByRole('button', { name: 'Approve machine' }))
    await within(dialog).findByText('The result is not confirmed yet')

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))

    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('The request was cancelled before its passkey proof was accepted. Nothing was changed.')
    expect(alert).toHaveTextContent('authorization-cancelled')
    expect(fake.service.applied).toBe(0)
    expect(fake.count(deletePath)).toBe(1)
    expect(vi.mocked(navigator.credentials.get)).toHaveBeenCalledTimes(1)
  })

  it("reports the service's recorded failure after a lost proof answer", async () => {
    const user = userEvent.setup()
    const fake = setup({
      lostProofReplies: 1,
      lostProofReached: true,
      settled: { result: { outcome: 'failed' as const, code: 'operation-failed', detail: 'the machine changed since the page was opened', link: null, invitation: null, invitationGone: false } },
    })
    const dialog = await openApprove(user)
    await user.click(await within(dialog).findByRole('button', { name: 'Approve machine' }))

    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('The change was not made')
    expect(alert).toHaveTextContent('the machine changed since the page was opened')
    expect(alert).toHaveTextContent('operation-failed')
    expect(within(dialog).queryByText('Done')).toBeNull()
    expect(fake.service.accepted).toBe(1)
    expect(fake.service.applied).toBe(0)
  })

  it('starts only one passkey ceremony and one proof submission for a rapid double click', async () => {
    const user = userEvent.setup()
    const fake = setup()
    const dialog = await openApprove(user)
    const confirm = await within(dialog).findByRole('button', { name: 'Approve machine' })

    fireEvent.click(confirm)
    fireEvent.click(confirm)

    expect(await within(dialog).findByText('Done')).toBeInTheDocument()
    expect(vi.mocked(navigator.credentials.get)).toHaveBeenCalledTimes(1)
    expect(fake.service.proofs).toBe(1)
    expect(fake.service.applied).toBe(1)
  })

  it('communicates uncertainty when the status endpoint cannot be read after a proof', async () => {
    const user = userEvent.setup()
    const fake = setup()
    fake.on(getPath, () => {
      throw new TypeError('offline')
    })
    const dialog = await openApprove(user)
    await user.click(await within(dialog).findByRole('button', { name: 'Approve machine' }))

    expect(await within(dialog).findByText('The result is not confirmed yet')).toBeInTheDocument()
    expect(within(dialog).getByText(/No answer yet/)).toBeInTheDocument()
    expect(within(dialog).queryByText('Done')).toBeNull()
    expect(within(dialog).queryByText('The change was not made')).toBeNull()
    expect(fake.service.proofs).toBe(1)
  })

  it('reports an expired authorization as its actual terminal state', async () => {
    const user = userEvent.setup()
    const fake = setup()
    // Pending until the tap is made: a terminal answer before then would race the click.
    fake.on(getPath, () => ({ body: fake.service.proved ? authorization({ state: 'expired', detail: 'The authorization ran out before it was used.' }) : authorization({ state: 'pending', result: null }) }))
    const dialog = await openApprove(user)
    await user.click(await within(dialog).findByRole('button', { name: 'Approve machine' }))

    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('authorization-expired')
    expect(alert).toHaveTextContent('The authorization ran out before it was used.')
    expect(within(dialog).queryByText('Done')).toBeNull()
  })

  it('cancels the request at the service when it is cancelled before the tap', async () => {
    const user = userEvent.setup()
    const fake = setup({ pendingPolls: 1000 })
    const dialog = await openApprove(user)
    await within(dialog).findByRole('button', { name: 'Approve machine' })
    await user.click(await within(dialog).findByRole('button', { name: 'Cancel' }))

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    await waitFor(() => expect(fake.count(deletePath)).toBe(1))
    expect(fake.count(approvePath)).toBe(0)
    expect(pendingAuthorization()).toBeNull()
  })

  it('keeps the request ready when the native passkey prompt is cancelled', async () => {
    const user = userEvent.setup()
    const fake = setup({ pendingPolls: 1000 })
    const dialog = await openApprove(user)
    await within(dialog).findByRole('button', { name: 'Approve machine' })
    vi.mocked(navigator.credentials.get).mockRejectedValueOnce(new DOMException('cancelled', 'NotAllowedError'))
    await user.click(within(dialog).getByRole('button', { name: 'Approve machine' }))
    expect(await within(dialog).findByText('Passkey prompt cancelled. Nothing was changed.')).toBeInTheDocument()
    expect(within(dialog).queryByRole('alert')).toBeNull()
    expect(within(dialog).getByRole('button', { name: 'Approve machine' })).toBeEnabled()
    expect(fake.count(proofPath)).toBe(0)
    expect(fake.count(deletePath)).toBe(0)
  })

  it('does not report a change when the authorization is refused, and says why', async () => {
    const user = userEvent.setup()
    const fake = setup()
    fake.on(getPath, () => ({ body: fake.service.proved ? authorization({ state: 'refused', detail: 'the passkey page refused it' }) : authorization({ state: 'pending', result: null }) }))
    const dialog = await openApprove(user)
    await user.click(await within(dialog).findByRole('button', { name: 'Approve machine' }))

    expect(await within(dialog).findByText('the passkey page refused it')).toBeInTheDocument()
    expect(within(dialog).getByRole('alert')).toHaveTextContent('The change was not made')
    expect(pendingAuthorization()).toBeNull()
  })

  it('shows a good tap whose change could not be made as not made, with the service sentence', async () => {
    const user = userEvent.setup()
    setup({ settled: { result: { outcome: 'failed' as const, code: 'operation-failed', detail: 'the machine changed since the page was opened', link: null, invitation: null, invitationGone: false } } })
    const dialog = await openApprove(user)
    await user.click(await within(dialog).findByRole('button', { name: 'Approve machine' }))

    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('the machine changed since the page was opened')
    expect(alert).toHaveTextContent('operation-failed')
  })

  it('does not wait for the service when it authorizes something other than what was asked, and cancels that authorization', async () => {
    const user = userEvent.setup()
    const fake = setup({ created: { operation: 'machine-disable' } })
    const dialog = await openApprove(user)

    expect(await within(dialog).findByText(/for a different request/)).toBeInTheDocument()
    expect(fake.count(getPath)).toBe(0)
    await waitFor(() => expect(fake.count(deletePath)).toBe(1))
    expect(opened).not.toHaveBeenCalled()
  })

  it('shows the service refusal as plain text and offers a fresh start (a new authorization)', async () => {
    const user = userEvent.setup()
    const fake = setup({ createReply: problem(409, 'operation-refused', 'this machine is not pending <b>x</b>') })
    const dialog = await openApprove(user)

    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('this machine is not pending <b>x</b>')
    expect(alert.querySelector('b')).toBeNull()
    expect(alert).toHaveTextContent('operation-refused')
    await user.click(within(dialog).getByRole('button', { name: 'Start over' }))
    fake.on(inlinePath, { status: 201, body: authorization({ link: null, proof: { mode: 'webauthn', payload: JSON.stringify({ bind: 'AQ', rpId: 'localhost', timeout: 60000 }) }, parameters: [{ name: 'fingerprint', value: machine().fingerprint }, { name: 'name', value: 'build-host' }] }) })
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }))
    await within(dialog).findByRole('button', { name: 'Approve machine' })
    await waitFor(() => expect(fake.count(inlinePath)).toBe(2))
  })

  it('every change asks for its own authorization (nothing is reused)', async () => {
    const user = userEvent.setup()
    const fake = signedIn()
    let nextId = 0
    fake.on(inlinePath, () => {
      const id = `auth-id-${++nextId}`
      const path = `/api/v1/authorizations/${id}`
      const pending = authorization({
        id, link: null, proof: { mode: 'webauthn', payload: JSON.stringify({ bind: 'AQ', rpId: 'localhost', timeout: 60000 }) },
      })
      let proved = false
      fake.on(`GET ${path}`, () => ({ body: proved ? { ...pending, state: 'consumed', result: applied } : pending }))
      fake.on(`POST ${path}/proof`, () => {
        proved = true
        return { body: { ok: true } }
      })
      return { status: 201, body: pending }
    })

    renderApp('/machines')
    for (const round of [1, 2]) {
      await user.click(await screen.findByRole('button', { name: /^approve/i }))
      const dialog = await screen.findByRole('dialog')
      await user.click(await within(dialog).findByRole('button', { name: 'Approve machine' }))
      await user.click(await within(dialog).findByRole('button', { name: 'Close' }))
      expect(fake.count(inlinePath)).toBe(round)
      expect(fake.count(`POST /api/v1/authorizations/auth-id-${round}/proof`)).toBe(1)
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
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
    await user.click(within(dialog).getByRole('button', { name: 'Continue' }))

    expect(days).toHaveAttribute('aria-invalid', 'true')
    expect(within(dialog).getByRole('alert')).toHaveTextContent(/whole number/)
    expect(days.getAttribute('aria-describedby')).toContain('error')
    expect(opened).not.toHaveBeenCalled()

    // Correcting the value takes the error away at once, without another Continue.
    await user.clear(days)
    await user.type(days, '30')
    expect(within(dialog).queryByRole('alert')).toBeNull()
    expect(days).not.toHaveAttribute('aria-invalid', 'true')
  })
})

describe('a tap is never lost: the page that comes back reads what the service made of it', () => {
  it('keeps only the id and the sentence of the waiting authorization in this tab, never the link or a parameter', async () => {
    const user = userEvent.setup()
    setup({ pendingPolls: 1000 })
    const dialog = await openApprove(user)
    await within(dialog).findByRole('button', { name: 'Cancel' })

    expect(pendingAuthorization()).toMatchObject({ id: 'auth-id-0001', operation: 'machine-approve', title: 'Approve this machine' })
    const text = JSON.stringify({ ...sessionStorage })
    expect(text).not.toContain('passkey-page-token')
    expect(text).not.toContain(machine().fingerprint)
    expect(JSON.stringify({ ...localStorage })).not.toContain('auth-id-0001')
  })

  it('a reloaded tab reports that its challenge must be restarted, with no mutation call', async () => {
    const fake = setup({ pendingPolls: 1000 })
    setPendingAuthorization({ id: 'auth-id-0001', operation: 'machine-approve', title: 'Approve this machine', summary: 'Approve machine ab12 cd34 ef56 ab12 as "ci box".', done: 'Done.' })
    renderApp('/machines')

    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/This page was reloaded/)).toBeInTheDocument()
    expect(await within(dialog).findByRole('button', { name: 'Cancel' })).toBeInTheDocument()
    expect(within(dialog).getByText(/Approve machine ab12 cd34 ef56 ab12 as "ci box"\./)).toBeInTheDocument()
    expect(fake.calls.some((call) => call.method === 'POST')).toBe(false)
    expect(pendingAuthorization()?.id).toBe('auth-id-0001')
  })

  it('a lock that ended the session reads as locked when the public status says so', async () => {
    const fake = setup()
    fake.on(getPath, problem(401, 'session-required', 'no session'))
    fake.on('GET /api/v1/status', { body: status({ locked: true }) })
    setPendingAuthorization({ id: 'auth-id-0001', operation: 'lock', title: 'Lock the authority', summary: 'Lock the authority now.', done: 'Done.' })
    renderApp('/machines')

    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('The authority is locked.')).toBeInTheDocument()
    expect(within(dialog).queryByRole('alert')).toBeNull()
  })

  it('a lock whose result cannot be read, with the authority unlocked, stays unconfirmed', async () => {
    const fake = setup()
    fake.on(getPath, problem(401, 'session-required', 'no session'))
    fake.on('GET /api/v1/status', { body: status({ locked: false }) })
    setPendingAuthorization({ id: 'auth-id-0001', operation: 'lock', title: 'Lock the authority', summary: 'Lock the authority now.', done: 'Done.' })
    renderApp('/machines')

    const dialog = await screen.findByRole('dialog')
    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('Result not confirmed')
    expect(alert).toHaveTextContent(/audit history/)
    expect(within(dialog).queryByText('The authority is locked.')).toBeNull()
  })

  it('a session that ended before the result could be read says so, and where to look', async () => {
    const fake = setup()
    fake.on(getPath, problem(404, 'not-found', 'no such authorization for this caller'))
    setPendingAuthorization({ id: 'auth-id-0001', operation: 'machine-approve', title: 'Approve this machine', summary: 'x', done: 'Done.' })
    renderApp('/machines')

    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(/audit history/)
    expect(pendingAuthorization()).toBeNull()
  })
})
