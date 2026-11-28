import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { approvalDetail, approvalItem, authorization, grant, problem, session, signedIn, status, violations } from '../../test/fakeApi'
import { renderApp } from '../../test/render'

const challengePath = 'POST /api/v1/approvals/req-0001/challenge'
const approvePath = 'POST /api/v1/approvals/req-0001/approve'
const denyPath = 'POST /api/v1/approvals/req-0001/deny'
const detailPath = 'GET /api/v1/approvals/req-0001'

/** The challenge the service prepares for one request. With salt the payload also carries a slot salt, which a run approval must never use. */
async function challenge(salt: boolean) {
  return {
    flowId: 'flow-0001',
    mode: 'webauthn' as const,
    payload: { bind: 'AQIDBA', rpId: 'localhost', timeout: 60000, ...(salt ? { salt: 'BQYHCA' } : {}) },
    expiresAt: new Date(Date.now() + 120_000).toISOString(),
  }
}

let credentials: { get: ReturnType<typeof vi.fn> }
beforeEach(() => {
  credentials = {
    get: vi.fn(async () => ({
      rawId: new Uint8Array([1]).buffer,
      response: { authenticatorData: new Uint8Array([2]).buffer, clientDataJSON: new Uint8Array([3]).buffer, signature: new Uint8Array([4]).buffer },
      getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(7).buffer } } }),
    })),
  }
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: credentials })
})
afterEach(() => {
  vi.useRealTimers()
})

async function enabledApprove() {
  const approve = await screen.findByRole('button', { name: 'Approve once' })
  await waitFor(() => expect(approve).toBeEnabled(), { timeout: 4000 })

  return approve
}

describe('approvals', () => {
  it('lists the run requests that wait, with a way to review each', async () => {
    const later = approvalItem({ requestId: 'req-0002', expiresAt: '2026-11-09T10:20:00Z' })
    const api = signedIn({ 'GET /api/v1/approvals': { body: { items: [later, approvalItem({ scriptName: 'deploy.cmd' })], nextCursor: null, serverTime: '2026-11-09T10:00:00Z' } } })
    renderApp('/access')

    const table = await screen.findByRole('table', { name: 'Run requests' })
    const rows = within(table).getAllByRole('row').slice(1)
    expect(within(rows[0]!).getByText('build box')).toBeInTheDocument()
    expect(within(rows[0]!).getByText('deploy.cmd')).toBeInTheDocument()
    expect(within(rows[0]!).getByText('5 min')).toBeInTheDocument()
    expect(within(rows[1]!).getByText('20 min')).toBeInTheDocument()
    expect(within(table).queryByText('DEPLOY_TOKEN')).not.toBeInTheDocument()
    expect(within(rows[0]!).getByRole('link', { name: /review/i })).toHaveAttribute('href', '/access/req-0001')
    expect(api.calls.find(call => call.path === '/api/v1/approvals')?.query.get('limit')).toBe('64')
    expect(await violations(document.body)).toEqual([])
  })

  it('says so when nothing waits, and offers Access in the navigation', async () => {
    signedIn()
    renderApp('/access')

    expect(await screen.findByText('No run request is waiting.')).toBeInTheDocument()
    expect(within(screen.getByRole('navigation', { name: 'Main' })).getByRole('link', { name: 'Access' })).toBeInTheDocument()
  })

  it('shows the Overview a waiting request', async () => {
    signedIn({ 'GET /api/v1/approvals': { body: { items: [approvalItem()], nextCursor: null, serverTime: '2026-11-09T10:00:00Z' } } })
    renderApp('/')

    expect(await screen.findByRole('link', { name: '1 run request is waiting' })).toBeInTheDocument()
  })

  it('shows what would run and why, with the code that runs, before any decision', async () => {
    signedIn({ [detailPath]: { body: approvalDetail() }, [challengePath]: { status: 201, body: await challenge(false) } })
    renderApp('/access/req-0001')

    expect(await screen.findByRole('dialog', { name: 'Run request from build box' })).toBeInTheDocument()
    expect(screen.getAllByText(/DEPLOY_TOKEN/).length).toBeGreaterThan(0)
    expect(screen.getByText('ship the release')).toBeInTheDocument()
    expect(screen.getByText('echo deploying')).toBeInTheDocument()
    expect(screen.getByText('More details')).toBeInTheDocument()
    expect(await violations(document.body)).toEqual([])
  })

  it('keeps a code-changes warning above the decision', async () => {
    signedIn({
      [detailPath]: { body: approvalDetail({ review: { ...approvalDetail().review!, codeChangeWarnings: [{ name: 'NODE_OPTIONS', why: 'loads a file before the program starts', value: '--require ./hook.js' }] } }) },
      [challengePath]: { status: 201, body: await challenge(false) },
    })
    renderApp('/access/req-0001')

    const warning = await screen.findByText('This changes how the program loads code or where it sends data')
    const approve = screen.getByRole('button', { name: 'Approve once' })
    expect(warning.compareDocumentPosition(approve) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(screen.getByText('NODE_OPTIONS=--require ./hook.js')).toBeInTheDocument()
  })

  it('shows the ordinary .env values the approval covers', async () => {
    signedIn({
      [detailPath]: { body: approvalDetail({ review: { ...approvalDetail().review!, shownEnvValues: [{ name: 'LOG_LEVEL', value: 'quiet' }] } }) },
      [challengePath]: { status: 201, body: await challenge(false) },
    })
    renderApp('/access/req-0001')

    expect(await screen.findByText('LOG_LEVEL=quiet')).toBeInTheDocument()
  })

  it('offers the times for a pre-approval and signs the chosen one', async () => {
    const fake = signedIn({
      [detailPath]: { body: approvalDetail({ review: { ...approvalDetail().review!, heading: 'Create a GRANT for this exact command.', times: [10, 60, 240], allowOnce: false } }) },
      [challengePath]: { status: 201, body: await challenge(false) },
      [approvePath]: { body: approvalDetail({ status: 'approved', review: null }) },
    })
    const user = userEvent.setup()
    renderApp('/access/req-0001')

    expect(await screen.findByText('Create a GRANT for this exact command.')).toBeInTheDocument()
    const more = await screen.findByRole('button', { name: 'Approve for longer' })
    await waitFor(() => expect(more).toBeEnabled(), { timeout: 4000 })
    expect(screen.getByRole('button', { name: 'Approve for 10 minutes' })).toBeInTheDocument()
    await user.click(more)
    await user.click(screen.getByRole('menuitem', { name: 'Approve for 1 hour' }))

    await waitFor(() => expect(fake.count(approvePath)).toBe(1))
    const options = credentials.get.mock.calls[0]![0].publicKey
    const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([1, 2, 3, 4, ...new TextEncoder().encode('reuse=60')])))
    expect(new Uint8Array(options.challenge)).toEqual(expected)
    expect((fake.calls.find((call) => call.path === '/api/v1/approvals/req-0001/approve')!.body as { minutes: number }).minutes).toBe(60)
  })

  it('approves once by default, with the longer times behind the arrow', async () => {
    const fake = signedIn({
      [detailPath]: { body: approvalDetail({ review: { ...approvalDetail().review!, times: [10, 60, 1000000] } }) },
      [challengePath]: { status: 201, body: await challenge(false) },
      [approvePath]: { body: approvalDetail({ status: 'approved', review: null }) },
    })
    const user = userEvent.setup()
    renderApp('/access/req-0001')

    const more = await screen.findByRole('button', { name: 'Approve for longer' })
    await waitFor(() => expect(more).toBeEnabled(), { timeout: 4000 })
    await user.click(more)
    expect(screen.getAllByRole('menuitem').map((item) => item.textContent)).toEqual(['Approve for 10 minutes', 'Approve for 1 hour', 'Approve always'])
    await user.click(screen.getByRole('menuitem', { name: 'Approve for 10 minutes' }))

    await waitFor(() => expect(fake.count(approvePath)).toBe(1))
    expect((fake.calls.find((call) => call.path === '/api/v1/approvals/req-0001/approve')!.body as { minutes: number }).minutes).toBe(10)
    expect(await screen.findByText('Approved. build box can run it now and again for 10 minutes.')).toBeInTheDocument()
  })

  it('shows the extra lines the passkey signs', async () => {
    signedIn({
      [detailPath]: { body: approvalDetail({ review: { ...approvalDetail().review!, extraLines: ['This keeps the key for the grant.'] } }) },
      [challengePath]: { status: 201, body: await challenge(false) },
    })
    renderApp('/access/req-0001')

    expect(await screen.findByText('This keeps the key for the grant.')).toBeInTheDocument()
  })

  it('asks for the challenge when the request opens, and starts no passkey prompt until Approve is pressed', async () => {
    const fake = signedIn({ [detailPath]: { body: approvalDetail() }, [challengePath]: { status: 201, body: await challenge(false) } })
    renderApp('/access/req-0001')

    await screen.findByRole('dialog', { name: 'Run request from build box' })
    await waitFor(() => expect(fake.count(challengePath)).toBe(1))
    expect(credentials.get).not.toHaveBeenCalled()
    expect(fake.count(approvePath)).toBe(0)
  })

  it('keeps Approve disabled for a moment, with Deny first and focused', async () => {
    signedIn({ [detailPath]: { body: approvalDetail() }, [challengePath]: { status: 201, body: await challenge(false) } })
    renderApp('/access/req-0001')

    const deny = await screen.findByRole('button', { name: 'Deny' })
    expect(deny).toHaveFocus()
    expect(screen.getByRole('button', { name: 'Approve once' })).toBeDisabled()
    await enabledApprove()
  })

  it('approves once with one passkey tap, signing the request challenge and sending its proof', async () => {
    const fake = signedIn({
      [detailPath]: { body: approvalDetail() },
      [challengePath]: { status: 201, body: await challenge(false) },
      [approvePath]: { body: approvalDetail({ status: 'approved', review: null }) },
    })
    renderApp('/access/req-0001')

    const approve = await enabledApprove()
    fireEvent.click(approve)
    fireEvent.click(approve)

    await waitFor(() => expect(fake.count(approvePath)).toBe(1))
    expect(credentials.get).toHaveBeenCalledTimes(1)
    const options = credentials.get.mock.calls[0]![0].publicKey
    expect(options.rpId).toBe('localhost')
    expect(options.userVerification).toBe('required')
    expect(options.extensions).toBeUndefined()
    // The passkey signs SHA-256(bind || "reuse=0").
    const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array([1, 2, 3, 4, ...new TextEncoder().encode('reuse=0')])))
    expect(new Uint8Array(options.challenge)).toEqual(expected)
    const body = fake.calls.find((call) => call.path === '/api/v1/approvals/req-0001/approve')!.body as { flowId: string; proof: Record<string, string>; prf?: unknown }
    expect(body.flowId).toBe('flow-0001')
    expect(body.proof).toEqual({ id: 'AQ', authenticatorData: 'Ag', clientDataJSON: 'Aw', signature: 'BA' })
    expect(body.prf).toBeUndefined()
    // Back on the list, with what happened said at the top: no extra click to get there.
    expect(await screen.findByRole('heading', { level: 1, name: 'Access' })).toBeInTheDocument()
    expect(await screen.findByText(/^Approved\. .* can run it now\.$/)).toBeInTheDocument()
  })

  it('never asks the passkey for a PRF output, even when the payload carries a salt, and sends none', async () => {
    const fake = signedIn({
      [detailPath]: { body: approvalDetail() },
      [challengePath]: { status: 201, body: await challenge(true) },
      [approvePath]: { body: approvalDetail({ status: 'approved', review: null }) },
    })
    renderApp('/access/req-0001')

    fireEvent.click(await enabledApprove())

    await waitFor(() => expect(fake.count(approvePath)).toBe(1))
    const options = credentials.get.mock.calls[0]![0].publicKey
    expect(options.extensions).toBeUndefined()
    const body = fake.calls.find((call) => call.path === '/api/v1/approvals/req-0001/approve')!.body as Record<string, unknown>
    expect(Object.keys(body).sort()).toEqual(['flowId', 'proof'])
    expect(JSON.stringify(body)).not.toContain('BwcH')
  })
  it('says nothing was approved when the passkey prompt is cancelled, and asks for a fresh challenge', async () => {
    credentials.get.mockRejectedValueOnce(new DOMException('cancelled', 'NotAllowedError'))
    const fake = signedIn({ [detailPath]: { body: approvalDetail() }, [challengePath]: { status: 201, body: await challenge(false) } })
    renderApp('/access/req-0001')

    fireEvent.click(await enabledApprove())

    expect(await screen.findByText('Passkey prompt cancelled. Nothing was approved.')).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(fake.count(approvePath)).toBe(0)
    await waitFor(() => expect(fake.count(challengePath)).toBe(2))
  })

  it('denies without a passkey', async () => {
    const fake = signedIn({
      [detailPath]: { body: approvalDetail() },
      [challengePath]: { status: 201, body: await challenge(false) },
      [denyPath]: { body: approvalDetail({ status: 'denied', review: null }) },
    })
    const user = userEvent.setup()
    renderApp('/access/req-0001')

    await user.click(await screen.findByRole('button', { name: 'Deny' }))

    await waitFor(() => expect(fake.count(denyPath)).toBe(1))
    expect(credentials.get).not.toHaveBeenCalled()
  })

  it('a Deny made while the challenge is still being asked for waits for its answer, so the challenge never meets a decided request', async () => {
    // The service refuses a challenge for a request that is already decided (409 request-not-pending), as the real one does.
    let decided = false
    let release: () => void = () => undefined
    const held = new Promise<void>((resolve) => {
      release = resolve
    })
    const answered = await challenge(false)
    const fake = signedIn({
      [detailPath]: { body: approvalDetail() },
      [challengePath]: async () => {
        await held

        return decided ? problem(409, 'request-not-pending', 'this request is no longer pending') : { status: 201, body: answered }
      },
      [denyPath]: () => {
        decided = true

        return { body: approvalDetail({ status: 'denied', review: null }) }
      },
    })
    const user = userEvent.setup()
    renderApp('/access/req-0001')
    await waitFor(() => expect(fake.count(challengePath)).toBe(1))

    await user.click(await screen.findByRole('button', { name: 'Deny' }))
    expect(fake.count(denyPath)).toBe(0)

    release()
    await waitFor(() => expect(fake.count(denyPath)).toBe(1))
    const replies = await Promise.all(vi.mocked(fetch).mock.results.map(async (result) => (result.value as Promise<Response>).then((response) => response.status)))
    expect(replies).not.toContain(409)
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('shows what became of a request that is no longer pending', async () => {
    signedIn({ [detailPath]: { body: approvalDetail({ status: 'expired', review: null }) } })
    renderApp('/access/req-0001')

    expect(await screen.findByText('This request expired.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve once' })).toBeNull()
  })

  it('shows the service refusal as plain text', async () => {
    signedIn({ [detailPath]: problem(404, 'request-unavailable', 'no request is available for that id') })
    renderApp('/access/req-0001')

    expect(await screen.findByRole('alert')).toHaveTextContent('no request is available for that id')
  })
})

describe('grants: used once-only grants', () => {
  const used = grant({ id: 'g-once0001', state: 'consumed', status: 'consumed', usage: 'once', consumed: '2026-11-09T09:00:05Z', expires: null, ends: 'used 2026-11-09T09:00:05.0000000Z', actions: ['extend'], repeatTimes: [60, 120, 240, 480, 1440, 10080, 43200, 1000000] })

  it('shows used approvals and lets a person allow repeat runs', async () => {
    const user = userEvent.setup()
    let proved = false
    const fake = signedIn({
      'GET /api/v1/grants': { body: { items: [used, grant({ id: 'g-new00002', replaces: 'g-once0001' })] } },
      'POST /api/v1/authorizations/auth-id-0001/proof': () => {
        proved = true
        return { body: { ok: true } }
      },
      'GET /api/v1/authorizations/auth-id-0001': () => ({ body: authorization({
        operation: 'grant-extend', state: proved ? 'consumed' : 'pending',
        result: proved ? { outcome: 'applied', code: null, detail: null, link: null, invitation: null, invitationGone: false } : null,
      }) }),
    })
    renderApp('/access')

    const table = within(await screen.findByRole('table', { name: 'Grants' }))
    expect(table.getByText('Used once')).toBeInTheDocument()
    expect(table.queryByRole('button', { name: /Allow repeat runs/ })).toBeNull()
    await user.click(table.getByRole('button', { name: /View grant g-once0001/ }))
    const details = within(await screen.findByRole('dialog', { name: 'Grant for deploy.cmd' }))
    expect(details.getByText('Used')).toBeInTheDocument()
    expect(details.getByText('DEPLOY_TOKEN')).toBeInTheDocument()
    await user.click(details.getByRole('button', { name: /Allow repeat runs/ }))
    const choices = await screen.findAllByRole('menuitem')
    expect(choices.map(option => option.textContent)).toEqual(['1 hour', '2 hours', '4 hours', '8 hours', '24 hours', '7 days', '30 days', 'Always'])
    expect(credentials.get).not.toHaveBeenCalled()
    await user.click(screen.getByRole('menuitem', { name: '30 days' }))
    await waitFor(() => expect(credentials.get).toHaveBeenCalledTimes(1))
    expect(fake.calls.find((call) => call.path === '/api/v1/authorizations/inline')?.body).toEqual({ operation: 'grant-extend', parameters: { id: 'g-once0001', minutes: 43200 } })
    expect(fake.count('POST /api/v1/authorizations/auth-id-0001/proof')).toBe(1)
    expect(await screen.findByText('Extended grant g-once0001 for 30 days.')).toBeVisible()
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('removes expired grants from the list as it refreshes', async () => {
    const running = grant({ id: 'g-ending' })
    const fake = signedIn({ 'GET /api/v1/grants': { body: { items: [running, used] } } })
    renderApp('/access')

    const table = within(await screen.findByRole('table', { name: 'Grants' }))
    expect(table.getByRole('button', { name: /View grant g-ending/ })).toBeVisible()
    fake.on('GET /api/v1/grants', { body: { items: [{ ...running, state: 'expired', actions: ['renew'] }, used] } })
    await waitFor(() => expect(table.queryByRole('button', { name: /View grant g-ending/ })).not.toBeInTheDocument(), { timeout: 5000 })
    expect(table.getByRole('button', { name: /View grant g-once0001/ })).toBeVisible()
  })
})

describe('convenience passkey sessions', () => {
  it('can manage grants and view secret names without secret change controls', async () => {
    const user = userEvent.setup()
    signedIn({
      'GET /api/v1/session': { body: session({ admin: null, identity: 'phone', scope: 'approval', capabilities: ['approvals.read', 'approvals.decide', 'admin.read', 'grants.decide'] }) },
      'GET /api/v1/secrets': { body: { items: ['TOKEN'] } },
    })
    renderApp('/access')

    await user.click(await screen.findByRole('button', { name: /View grant grant-0001/ }))
    const details = within(await screen.findByRole('dialog'))
    expect(details.getByRole('button', { name: /^Extend\s*grant grant-0001$/ })).toBeInTheDocument()
    expect(details.getByRole('button', { name: /^Revoke\s*grant grant-0001$/ })).toBeInTheDocument()
    await user.click(details.getByRole('button', { name: 'Close' }))
    await user.click(screen.getByRole('link', { name: 'Secrets' }))
    const secrets = await screen.findByRole('list', { name: 'Secrets' })
    expect(within(secrets).getByText('TOKEN', { exact: true })).toBeVisible()
    expect(screen.queryByLabelText('Value')).toBeNull()
    expect(screen.queryByRole('button', { name: /remove secret/i })).toBeNull()
  })
})

describe('grant review', () => {
  it('shows locked review text with no way to open it but the unlock', async () => {
    const user = userEvent.setup()
    signedIn({
      'GET /api/v1/status': () => ({ body: status({ reviewOpen: false }) }),
      'GET /api/v1/grants/grant-0001/review': () => ({ body: { state: 'locked', text: null, verified: true } }),
    })
    renderApp('/access')

    await user.click(await screen.findByRole('button', { name: /View grant grant-0001/ }))
    await user.click(await screen.findByRole('button', { name: /^Review\s*grant grant-0001$/ }))
    expect(await screen.findByText('Review text opens when an administrator unlocks the authority with an admin passkey.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /tap to review/i })).toBeNull()
    expect(await violations(document.body)).toEqual([])
  })

  it('renders open review text literally', async () => {
    const user = userEvent.setup()
    const text = 'Command: deploy <script>token-canary</script>'
    signedIn({
      'GET /api/v1/status': () => ({ body: status({ reviewOpen: true }) }),
      'GET /api/v1/grants/grant-0001/review': () => ({ body: { state: 'open', text, verified: true } }),
    })
    renderApp('/access')

    await user.click(await screen.findByRole('button', { name: /View grant grant-0001/ }))
    await user.click(await screen.findByRole('button', { name: /^Review\s*grant grant-0001$/ }))
    expect((await screen.findByText(text)).tagName).toBe('PRE')
    expect(document.querySelector('pre script')).toBeNull()
    expect(await violations(document.body)).toEqual([])
  })

  it('says an ended grant keeps no review text and an unverified grant is not used', async () => {
    const user = userEvent.setup()
    signedIn({
      'GET /api/v1/grants': { body: { items: [grant({ id: 'g-ended001', status: 'revoked', state: 'revoked', actions: [] }), grant({ id: 'g-planted1', verified: false })] } },
      'GET /api/v1/grants/g-planted1/review': { body: { state: 'locked', text: null, verified: false } },
    })
    renderApp('/access')

    await user.click(await screen.findByRole('button', { name: /View grant g-ended001/ }))
    const details = within(await screen.findByRole('dialog'))
    expect(details.getByText('No review text is kept for an ended grant.')).toBeInTheDocument()
    expect(details.queryByRole('button', { name: /grant g-ended001$/ })).toBeNull()
    await user.click(details.getByRole('button', { name: 'Close' }))
    await user.click(screen.getByRole('button', { name: /View grant g-planted1/ }))
    expect(within(await screen.findByRole('dialog')).getByText('This grant is not verified and is not used.')).toBeVisible()
    expect(await violations(document.body)).toEqual([])
  })
})
