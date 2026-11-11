import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { pendingAuthorization } from '../../api/client'
import { authorization, signedIn, violations } from '../../test/fakeApi'
import { renderApp } from '../../test/render'

let opened: ReturnType<typeof vi.spyOn>
beforeEach(() => {
  opened = vi.spyOn(window, 'open').mockReturnValue(null)
})
afterEach(() => {
  opened.mockRestore()
})

const BUNDLE = 'ws-invite-SECRETBUNDLE'
const invitationResult = (extra = {}) => ({ outcome: 'applied' as const, code: null, detail: null, link: null, invitation: { id: 'inv-0001', expires: '2026-11-09T10:10:00Z', bundle: BUNDLE }, invitationGone: false, ...extra })
const createReplies = {
  'GET /api/v1/machines': { body: { items: [] } },
  'POST /api/v1/authorizations': { status: 201, body: authorization({ operation: 'pairing-create', parameters: [] }) },
}

describe('machines: pairing is part of the view', () => {
  it('has no Pairing entry in the navigation, and the old address leads here', async () => {
    signedIn()
    renderApp('/pairing')

    expect(await screen.findByRole('heading', { level: 1, name: 'Machines' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Pairing' })).toBeNull()
  })

  it('shows a machine that paired as a card to check and approve, with its name filled in from the host name', async () => {
    const user = userEvent.setup()
    signedIn()
    renderApp('/machines')
    const section = await screen.findByRole('region', { name: /paired and is waiting/i })
    expect(within(section).getByRole('heading', { name: 'build-host' })).toBeInTheDocument()
    expect(within(section).getByText('ab12 cd34 ef56 ab12')).toBeInTheDocument()
    expect(screen.getAllByText('ab12 cd34 ef56 ab12')).toHaveLength(1)
    expect(await violations(document.body)).toEqual([])

    await user.click(within(section).getByRole('button', { name: /^approve/i }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByLabelText(/friendly name/i)).toHaveValue('build-host')
  })

  it('lists invitations by status with no bundle, and revokes with its own authorization', async () => {
    const user = userEvent.setup()
    signedIn({
      'GET /api/v1/machines': { body: { items: [] } },
      'GET /api/v1/pairing/invitations': { body: { items: [{ id: 'inv-0001', status: 'pending', created: '2026-11-09T10:00:00Z', expires: '2026-11-09T10:10:00Z', ended: null, machine: null, canRevoke: true }] } },
      'POST /api/v1/authorizations': { status: 201, body: authorization({ operation: 'pairing-revoke', parameters: [{ name: 'id', value: 'inv-0001' }] }) },
    })
    renderApp('/machines')
    const list = await screen.findByRole('list', { name: 'Invitations' })
    expect(within(list).getByText('pending')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('ws-invite')

    await user.click(within(list).getByRole('button', { name: /revoke/i }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Continue to passkey' }))
    await waitFor(() => expect(opened).toHaveBeenCalledOnce())
  })

  it('creates an invitation in one step and shows the bundle once, never keeping it in storage or the address', async () => {
    const user = userEvent.setup()
    const fake = signedIn({
      ...createReplies,
      'GET /api/v1/authorizations/auth-id-0001': (call) => ({
        body: authorization({ operation: 'pairing-create', state: 'consumed', parameters: [], result: call.query.get('collect') === 'invitation' ? invitationResult() : invitationResult({ invitation: null }) }),
      }),
    })
    renderApp('/machines')
    await user.click(await screen.findByRole('button', { name: 'Add a machine' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))

    expect(await within(dialog).findByText(BUNDLE)).toBeInTheDocument()
    expect(fake.calls.filter((call) => call.method !== 'GET').map((call) => call.method + ' ' + call.path)).toEqual(['POST /api/v1/authorizations'])
    expect(JSON.stringify({ ...sessionStorage, ...localStorage })).not.toContain(BUNDLE)
    expect(window.location.href).not.toContain(BUNDLE)
    expect(pendingAuthorization()).toBeNull()
    expect(await violations(dialog)).toEqual([])
  })

  it('says an invitation that was not collected cannot be shown again', async () => {
    const user = userEvent.setup()
    signedIn({
      ...createReplies,
      'GET /api/v1/authorizations/auth-id-0001': { body: authorization({ operation: 'pairing-create', state: 'consumed', parameters: [], result: invitationResult({ invitation: null, invitationGone: true }) }) },
    })
    renderApp('/machines')
    await user.click(await screen.findByRole('button', { name: 'Add a machine' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Continue to passkey' }))

    expect(await within(dialog).findByText(/cannot be shown again/)).toBeInTheDocument()
  })
})
