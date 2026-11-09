import { cleanup, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { authorization, machine, problem, signedIn, violations } from '../../test/fakeApi'
import { renderApp } from '../../test/render'

const approvePath = 'POST /api/v1/machines/' + machine().fingerprint + '/approve'

/** The machines view with one pending machine; the service creates an authorization that becomes verified after `pendingPolls` looks. */
function setup(options: { pendingPolls?: number; state?: 'verified' | 'refused' | 'expired'; created?: Partial<ReturnType<typeof authorization>>; mutation?: ReturnType<typeof problem> | null } = {}) {
  let looks = 0
  const fake = signedIn({
    'POST /api/v1/authorizations': {
      status: 201,
      body: authorization({ parameters: [{ name: 'fingerprint', value: machine().fingerprint }, { name: 'name', value: 'ci box' }], ...options.created }),
    },
    'GET /api/v1/authorizations/auth-id-0001': () => {
      looks++

      return { body: authorization({ state: looks > (options.pendingPolls ?? 1) ? (options.state ?? 'verified') : 'pending', detail: options.state === 'refused' ? 'the passkey page refused it' : null }) }
    },
    [approvePath]: options.mutation ?? { body: { operation: 'machine-approve', outcome: 'applied', link: null } },
  })

  return fake
}

async function openApprove(user: ReturnType<typeof userEvent.setup>, name = 'ci box') {
  renderApp('/machines')
  await user.click(await screen.findByRole('button', { name: /approve/i }))
  const dialog = await screen.findByRole('dialog')
  const field = within(dialog).getByLabelText(/friendly name/i)
  await user.clear(field)
  await user.type(field, name)

  return dialog
}

describe('an administrative change', () => {
  it('names the exact operation and parameters, needs the tap, then performs the one mutation with the authorization id', async () => {
    const user = userEvent.setup()
    const fake = setup()
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Review' }))

    // The review names the operation and every parameter, before anything is asked of the service.
    expect(within(dialog).getByText('machine-approve')).toBeInTheDocument()
    expect(within(dialog).getByText(machine().fingerprint)).toBeInTheDocument()
    expect(within(dialog).getByText('ci box')).toBeInTheDocument()
    expect(fake.count('POST /api/v1/authorizations')).toBe(0)
    expect(await violations(dialog)).toEqual([])

    await user.click(within(dialog).getByRole('button', { name: /ask for passkey authorization/i }))
    const open = await within(dialog).findByRole('link', { name: /open the passkey page/i })
    expect(open).toHaveAttribute('href', 'http://localhost:54321/passkey-page-token')
    expect(open).toHaveAttribute('target', '_blank')
    expect(open.getAttribute('rel')).toContain('noopener')
    expect(within(dialog).getByText(/Approve this machine ab12 cd34 ef56 ab12 as "ci box"/)).toBeInTheDocument()
    expect(fake.calls.find((call) => call.path === '/api/v1/authorizations')?.body).toEqual({ operation: 'machine-approve', parameters: { fingerprint: machine().fingerprint, name: 'ci box' } })
    // No mutation before the tap is verified.
    expect(fake.count(approvePath)).toBe(0)

    await waitFor(() => expect(fake.count(approvePath)).toBe(1))
    expect(fake.calls.find((call) => call.path.endsWith('/approve'))?.body).toEqual({ authorization: 'auth-id-0001', name: 'ci box' })
    expect(fake.calls.find((call) => call.path.endsWith('/approve'))?.headers['X-Admin-Token']).toBe('session-secret-1')
    expect(await within(dialog).findByText(/Approve machine ab12 cd34 ef56 ab12 as "ci box"\./)).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Close' })).toBeInTheDocument()
  })

  it('does nothing when it is cancelled before the tap', async () => {
    const user = userEvent.setup()
    const fake = setup({ pendingPolls: 1000 })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Review' }))
    await user.click(within(dialog).getByRole('button', { name: /ask for passkey authorization/i }))
    await within(dialog).findByRole('link', { name: /open the passkey page/i })
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(fake.count(approvePath)).toBe(0)
  })

  it('does not perform the change when the authorization is refused, and says why', async () => {
    const user = userEvent.setup()
    const fake = setup({ state: 'refused' })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Review' }))
    await user.click(within(dialog).getByRole('button', { name: /ask for passkey authorization/i }))

    expect(await within(dialog).findByText('the passkey page refused it')).toBeInTheDocument()
    expect(within(dialog).getByRole('alert')).toHaveTextContent('The change was not made')
    expect(fake.count(approvePath)).toBe(0)
  })

  it('does not perform the change when the service authorizes something other than what was asked', async () => {
    const user = userEvent.setup()
    const fake = setup({ created: { operation: 'machine-disable', parameters: [{ name: 'fingerprint', value: machine().fingerprint }] } })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Review' }))
    await user.click(within(dialog).getByRole('button', { name: /ask for passkey authorization/i }))

    expect(await within(dialog).findByText(/other than what was asked/)).toBeInTheDocument()
    expect(fake.count('GET /api/v1/authorizations/auth-id-0001')).toBe(0)
    expect(fake.count(approvePath)).toBe(0)
  })

  it('shows the service refusal of the mutation as plain text and offers a fresh start (a new authorization)', async () => {
    const user = userEvent.setup()
    const fake = setup({ mutation: problem(403, 'authorization-invalid', 'the authorization is not valid for this change <b>x</b>') })
    const dialog = await openApprove(user)
    await user.click(within(dialog).getByRole('button', { name: 'Review' }))
    await user.click(within(dialog).getByRole('button', { name: /ask for passkey authorization/i }))

    const alert = await within(dialog).findByRole('alert')
    expect(alert).toHaveTextContent('the authorization is not valid for this change <b>x</b>')
    expect(alert.querySelector('b')).toBeNull()
    expect(alert).toHaveTextContent('authorization-invalid')
    await user.click(within(dialog).getByRole('button', { name: 'Start over' }))
    await user.click(within(dialog).getByRole('button', { name: /ask for passkey authorization/i }))
    await waitFor(() => expect(fake.count('POST /api/v1/authorizations')).toBe(2))
  })

  it('every change asks for its own authorization (nothing is reused)', async () => {
    const user = userEvent.setup()
    const fake = setup()
    for (const round of [1, 2]) {
      const dialog = await openApprove(user, 'ci box')
      await user.click(within(dialog).getByRole('button', { name: 'Review' }))
      await user.click(within(dialog).getByRole('button', { name: /ask for passkey authorization/i }))
      await within(dialog).findByRole('button', { name: 'Close' })
      expect(fake.count('POST /api/v1/authorizations')).toBe(round)
      expect(fake.count(approvePath)).toBe(round)
      await user.click(within(dialog).getByRole('button', { name: 'Close' }))
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
    await user.click(within(dialog).getByRole('button', { name: 'Review' }))

    expect(days).toHaveAttribute('aria-invalid', 'true')
    expect(within(dialog).getByRole('alert')).toHaveTextContent(/whole number/)
    expect(days.getAttribute('aria-describedby')).toContain('error')
  })
})
