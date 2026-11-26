import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { entry, mount, signedIn, status } from '../../test/fakeApi'
import { renderApp } from '../../test/render'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('Secrets page', () => {
  it('lists the stored names and shows no values', async () => {
    signedIn({ 'GET /api/v1/secrets': { body: { items: ['DB_URL', 'API_KEY'] } } })
    renderApp('/secrets')
    expect(await screen.findByRole('heading', { name: 'DB_URL' })).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'API_KEY' })).toBeTruthy()
    expect(screen.getAllByRole('button', { name: /^Remove/ })).toHaveLength(2)
  })

  it('says so when nothing is stored', async () => {
    signedIn({ 'GET /api/v1/secrets': { body: { items: [] } } })
    renderApp('/secrets')
    expect(await screen.findByText('No secret is stored.')).toBeTruthy()
  })

  it('browses local and mounted secrets by path without offering to remove provider entries', async () => {
    const mounted = mount({ logicalPath: 'team' })
    const api = signedIn({
      'GET /api/v1/status': { body: status({ capabilities: { providers: true } }) },
      'GET /api/v1/secrets': { body: { items: ['apps/API_KEY', 'team/ops/TOKEN'] } },
      'GET /api/v1/mounts': { body: [mounted] },
      [`GET /api/v1/mounts/${mounted.id}/entries`]: { body: [entry({ logicalPath: 'team/ops/TOKEN' })] },
    })
    renderApp('/secrets')
    expect(await screen.findByText('Local')).toBeVisible()
    await userEvent.click(screen.getByText('apps', { exact: true }))
    expect(screen.getByRole('heading', { name: 'API_KEY' })).toBeVisible()
    expect(screen.getByText('apps/API_KEY', { exact: true })).toBeVisible()
    expect(screen.getByRole('button', { name: 'Remove secret apps/API_KEY' })).toBeVisible()
    expect(api.count(`GET /api/v1/mounts/${mounted.id}/entries`)).toBe(0)
    const providers = within(await screen.findByRole('list', { name: 'Provider mounts' }))
    await userEvent.click(providers.getByText('team/', { exact: true }))
    await userEvent.click(await providers.findByText('ops', { exact: true }))
    expect(providers.getByRole('heading', { name: 'TOKEN' })).toBeVisible()
    expect(providers.queryByRole('button', { name: /^Remove/ })).not.toBeInTheDocument()
  })

  it('prefills the name from the link and offers Replace for a stored name', async () => {
    signedIn({ 'GET /api/v1/secrets': { body: { items: ['DB_URL'] } } })
    renderApp('/secrets?name=DB_URL')
    const name = (await screen.findByLabelText('Name')) as HTMLInputElement
    expect(name.value).toBe('DB_URL')
    await userEvent.type(screen.getByLabelText('Value'), 'x')
    expect(await screen.findByRole('button', { name: 'Replace secret' })).toBeTruthy()
  })

  it('keeps Save disabled until both fields are filled, and never echoes the value', async () => {
    signedIn({ 'GET /api/v1/secrets': { body: { items: [] } } })
    renderApp('/secrets')
    const save = (await screen.findByRole('button', { name: 'Save secret' })) as HTMLButtonElement
    expect(save.disabled).toBe(true)
    await userEvent.type(screen.getByLabelText('Name'), 'NEW_ONE')
    expect(save.disabled).toBe(true)
    const value = screen.getByLabelText('Value') as HTMLInputElement
    await userEvent.type(value, 'hunter2')
    expect(save.disabled).toBe(false)
    expect(value.type).toBe('password')
  })

  it('cancels the pending removal when the passkey is not used', async () => {
    const api = signedIn({
      'GET /api/v1/secrets': { body: { items: ['DB_URL'] } },
      'POST /api/v1/secrets/removals': { status: 201, body: { id: 'rm-1', manifest: 'AQ', payload: { bind: 'AQ', rpId: 'localhost', timeout: 60000 } } },
      'DELETE /api/v1/secrets/entries/rm-1': { body: { ok: true } },
    })
    vi.stubGlobal('navigator', { ...navigator, credentials: { get: vi.fn().mockRejectedValue(new DOMException('no', 'NotAllowedError')) } })
    renderApp('/secrets')
    await userEvent.click(await screen.findByRole('button', { name: /^Remove/ }))
    expect(await screen.findByText('Passkey prompt cancelled. Nothing was changed.')).toBeTruthy()
    await waitFor(() => expect(api.count('DELETE /api/v1/secrets/entries/rm-1')).toBe(1))
    expect(api.count('POST /api/v1/secrets/removals/rm-1/save')).toBe(0)
  })
})
