import { cleanup, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { authorization, signedIn, violations } from '../../test/fakeApi'
import { renderApp } from '../../test/render'

const BUNDLE = 'wsp1;https://10.0.0.5:8790;AAAAAAAAAAAAAAAAAAAAAA;BBBBBBBBBBBBBBBBBBBBBB'
const invitation = (extra = {}) => ({ id: 'AAAAAAAAAAAAAAAAAAAAAA', status: 'pending', created: '2026-11-09T10:00:00Z', expires: '2026-11-09T10:10:00Z', ended: null, machine: null, canRevoke: true, ...extra })

function setup(items: unknown[] = []) {
  let polls = 0

  return signedIn({
    'GET /api/v1/pairing/invitations': () => ({ body: { items } }),
    'POST /api/v1/authorizations': { status: 201, body: authorization({ operation: 'pairing-create', sentence: 'Create a pairing invitation for https://10.0.0.5:8790, valid for 10 minutes.', parameters: [{ name: 'authority', value: 'https://10.0.0.5:8790' }] }) },
    'GET /api/v1/authorizations/auth-id-0001': () => {
      polls++

      return { body: authorization({ operation: 'pairing-create', state: polls > 1 ? 'verified' : 'pending' }) }
    },
    'POST /api/v1/pairing/invitations': { body: { operation: 'pairing-create', outcome: 'applied', link: null, invitation: { id: 'AAAAAAAAAAAAAAAAAAAAAA', expires: '2026-11-09T10:10:00Z', bundle: BUNDLE } } },
  })
}

afterEach(() => cleanup())

describe('the pairing view', () => {
  it('lists invitations by status only and never shows a code', async () => {
    setup([invitation(), invitation({ id: 'CCCCCCCCCCCCCCCCCCCCCC', status: 'consumed', canRevoke: false, machine: 'ab12 cd34 ef56 ab12', ended: '2026-11-09T10:05:00Z' })])
    renderApp('/pairing')
    const list = await screen.findByRole('list', { name: 'Invitations' })

    expect(within(list).getAllByRole('listitem')).toHaveLength(2)
    expect(within(list).getByText('pending')).toBeInTheDocument()
    expect(within(list).getByText('consumed')).toBeInTheDocument()
    expect(within(list).getAllByRole('button', { name: /revoke/i })).toHaveLength(1)
    expect(document.body.textContent).not.toContain('wsp1')
    expect(await violations(document.body)).toEqual([])
  })

  it('shows the invitation bundle once, after the tap, and not again once the dialog is closed', async () => {
    const user = userEvent.setup()
    const fake = setup()
    renderApp('/pairing')
    await user.click(await screen.findByRole('button', { name: 'Create an invitation' }))
    const dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: /ask for passkey authorization/i }))
    expect(fake.count('POST /api/v1/pairing/invitations')).toBe(0)
    expect(within(dialog).queryByDisplayValue(BUNDLE)).toBeNull()

    const box = await within(dialog).findByDisplayValue(BUNDLE)
    expect(box).toHaveAttribute('readonly')
    expect(within(dialog).getByText(/shown only now/i)).toBeInTheDocument()
    expect(fake.calls.find((call) => call.path === '/api/v1/pairing/invitations' && call.method === 'POST')?.body).toEqual({ authorization: 'auth-id-0001' })
    expect(await violations(dialog)).toEqual([])

    await user.click(within(dialog).getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(screen.queryByDisplayValue(BUNDLE)).toBeNull()
    expect(document.body.textContent).not.toContain('BBBBBBBBBBBBBBBBBBBBBB')
    // The list the page refreshed is statuses only: the bundle is nowhere on the page, in storage or in the address.
    expect(window.location.href).not.toContain('BBBB')
    expect(JSON.stringify({ ...localStorage })).not.toContain('BBBB')
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('BBBB')
  })
})
