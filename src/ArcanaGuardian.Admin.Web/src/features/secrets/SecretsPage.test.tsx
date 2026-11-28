import { webcrypto } from 'node:crypto'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { entry, mount, provider, session, signedIn, status } from '../../test/fakeApi'
import { toBase64Url } from '../../lib/passkey'
import { renderApp } from '../../test/render'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('Secrets page', () => {
  it('lists the stored names and shows no values', async () => {
    signedIn({ 'GET /api/v1/secrets': { body: { items: ['DB_URL', 'API_KEY'] } } })
    renderApp('/secrets')
    const tree = within(await screen.findByRole('list', { name: 'Secrets' }))
    expect(tree.getByText('DB_URL')).toBeVisible()
    expect(tree.getByText('API_KEY')).toBeVisible()
    expect(tree.getAllByRole('button', { name: /^Remove/ })).toHaveLength(2)
    expect(screen.getAllByRole('heading')).toEqual([screen.getByRole('heading', { name: 'Secrets', level: 1 })])
  })

  it('says so when nothing is stored', async () => {
    signedIn({ 'GET /api/v1/secrets': { body: { items: [] } } })
    renderApp('/secrets')
    expect(await screen.findByText('Add a secret or a mount secret provider.')).toBeTruthy()
  })

  it('puts manual and mounted secrets that share a path in one folder', async () => {
    const mounted = mount({ logicalPath: 'team' })
    const nested = mount({ id: 'nested-mount', logicalPath: 'team/ops/staging' })
    let showMounts = () => {}
    const pendingMounts = new Promise<void>(resolve => { showMounts = resolve })
    const api = signedIn({
      'GET /api/v1/status': { body: status({ capabilities: { providers: true } }) },
      'GET /api/v1/providers': { body: [] },
      'GET /api/v1/secrets': { body: { items: ['ROOT_KEY', 'team/ops/API_KEY'] } },
      'GET /api/v1/mounts': async () => {
        await pendingMounts
        return { body: [mounted, nested] }
      },
      [`GET /api/v1/mounts/${mounted.id}/entries`]: { body: [entry({ logicalPath: 'team/ops/TOKEN' })] },
      [`GET /api/v1/mounts/${nested.id}/entries`]: { body: [entry({ logicalPath: 'team/ops/staging/BUILD_KEY' })] },
    })
    renderApp('/secrets')
    expect(api.count(`GET /api/v1/mounts/${mounted.id}/entries`)).toBe(0)
    const tree = within(await screen.findByRole('list', { name: 'Secrets' }))
    expect(tree.getByText('ROOT_KEY', { exact: true })).toBeVisible()
    expect(tree.queryByText('Local', { exact: true })).not.toBeInTheDocument()
    await userEvent.click(await tree.findByText('team', { exact: true }))
    await userEvent.click(tree.getByText('ops', { exact: true }))
    showMounts()
    expect(await tree.findByText('TOKEN', { exact: true })).toBeVisible()
    expect(tree.getByText('team/ops/API_KEY', { exact: true })).toBeVisible()
    expect(tree.getByRole('button', { name: 'Remove secret team/ops/API_KEY' })).toBeVisible()
    expect(tree.queryByRole('button', { name: 'Remove secret team/ops/TOKEN' })).not.toBeInTheDocument()
    expect(api.count(`GET /api/v1/mounts/${nested.id}/entries`)).toBe(0)
    await userEvent.click(tree.getByText('staging', { exact: true }))
    expect(await tree.findByText('BUILD_KEY', { exact: true })).toBeVisible()
    expect(tree.getAllByText('ops', { exact: true })).toHaveLength(1)
  })

  it('opens an existing secret for editing from a prefilled link', async () => {
    signedIn({ 'GET /api/v1/secrets': { body: { items: ['DB_URL'] } } })
    renderApp('/secrets?name=DB_URL')
    const form = within(await screen.findByRole('dialog', { name: 'Edit secret' }))
    const name = form.getByLabelText(/^Name/) as HTMLInputElement
    expect(name.value).toBe('DB_URL')
    expect(form.getByLabelText('New value')).toHaveValue('')
    expect(form.getByRole('button', { name: 'Save changes' })).toBeDisabled()
  })

  it('edits the name and folder without requiring a replacement value', async () => {
    signedIn({ 'GET /api/v1/secrets': { body: { items: ['apps/DB_URL', 'apps/TAKEN'] } } })
    renderApp('/secrets')
    await userEvent.click(await screen.findByText('apps', { exact: true }))
    await userEvent.click(screen.getByRole('button', { name: 'Edit secret apps/DB_URL' }))
    const form = within(await screen.findByRole('dialog', { name: 'Edit secret' }))
    expect(form.getByLabelText('Folder path')).toHaveValue('apps')
    expect(form.getByLabelText('New value')).toHaveAttribute('type', 'password')
    const name = form.getByLabelText(/^Name/)
    const save = form.getByRole('button', { name: 'Save changes' })
    await userEvent.clear(name)
    await userEvent.type(name, 'TAKEN')
    expect(form.getByText('A secret already exists at this path.')).toBeVisible()
    expect(save).toBeDisabled()
    await userEvent.type(name, '_NEW')
    expect(form.getByLabelText('New value')).toHaveValue('')
    expect(save).toBeEnabled()
  })

  it('mounts a selected provider from Secrets with suggestions from the tree', async () => {
    const first = provider({ name: 'Team Vault', type: 'vault', actions: ['add-mount'] })
    const second = provider({ id: 'second-provider', name: 'Build Vault', type: 'vault', actions: ['add-mount'] })
    const api = signedIn({
      'GET /api/v1/status': { body: status({ capabilities: { providers: true } }) },
      'GET /api/v1/providers': { body: [first, second] },
      'GET /api/v1/mounts': { body: [] },
      'GET /api/v1/secrets': { body: { items: ['apps/API_KEY'] } },
      'POST /api/v1/providers/validate': { body: { ok: true, issues: [] } },
    })
    renderApp('/secrets')
    await userEvent.click(await screen.findByRole('button', { name: 'Mount provider' }))
    const dialog = within(await screen.findByRole('dialog', { name: 'Mount provider' }))
    await userEvent.selectOptions(dialog.getByLabelText(/^Provider/), 'Team Vault')
    const path = dialog.getByLabelText(/^Logical path/)
    const suggestions = document.getElementById(path.getAttribute('list') ?? '')
    expect(suggestions?.querySelector('option')?.value).toBe('apps/')
    await userEvent.type(path, 'apps/build')
    await userEvent.type(dialog.getByLabelText('Provider path'), 'old-root/')
    await userEvent.selectOptions(dialog.getByLabelText(/^Provider \(/), 'Build Vault')
    expect(dialog.getByLabelText('Provider path')).toHaveValue('')
    await userEvent.click(dialog.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(api.count('POST /api/v1/authorizations/inline')).toBe(1))
    expect(api.calls.find(call => call.path === '/api/v1/authorizations/inline')?.body?.parameters).toMatchObject({
      instance: second.id, path: 'apps/build', base: '',
    })
  })

  it('opens the form on demand and discards the draft when cancelled', async () => {
    signedIn({ 'GET /api/v1/secrets': { body: { items: [] } } })
    renderApp('/secrets')
    const add = await screen.findByRole('button', { name: 'Add secret' })
    expect(screen.queryByLabelText(/^Value/)).not.toBeInTheDocument()
    await userEvent.click(add)
    const form = within(await screen.findByRole('dialog', { name: 'Add secret' }))
    const save = form.getByRole('button', { name: 'Save secret' })
    expect(save).toBeDisabled()
    await userEvent.type(form.getByLabelText(/^Name/), 'NEW_ONE')
    expect(save).toBeDisabled()
    const value = form.getByLabelText(/^Value/)
    await userEvent.type(value, 'hunter2')
    expect(save).toBeEnabled()
    expect(value).toHaveAttribute('type', 'password')
    await userEvent.click(form.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await userEvent.click(add)
    const reopened = within(await screen.findByRole('dialog', { name: 'Add secret' }))
    expect(reopened.getByLabelText(/^Name/)).toHaveValue('')
    expect(reopened.getByLabelText(/^Value/)).toHaveValue('')
  })

  it('saves an addition and replacement together with one convenience passkey prompt', async () => {
    vi.stubGlobal('crypto', webcrypto)
    const key = await webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
    const publicKey = toBase64Url(await webcrypto.subtle.exportKey('raw', key.publicKey))
    const api = signedIn({
      'GET /api/v1/session': { body: session({ scope: 'approval', capabilities: ['admin.read', 'secrets.write'] }) },
      'GET /api/v1/secrets': { body: { items: ['DB_URL'] } },
      'POST /api/v1/secrets/entries': { status: 201, body: {
        id: 'entry-123', publicKey, payload: { bind: 'AQ', rpId: 'localhost', timeout: 60000 },
        fields: [{ name: 'DB_URL', replace: true }, { name: 'API_KEY', replace: false }],
      } },
      'POST /api/v1/secrets/entries/entry-123/seal': { body: { ok: true, manifest: 'signed batch text' } },
      'POST /api/v1/secrets/entries/entry-123/save': { body: { ok: true } },
    })
    const bytes = new Uint8Array([1]).buffer
    const assert = vi.fn().mockResolvedValue({ rawId: bytes, response: { authenticatorData: bytes, clientDataJSON: bytes, signature: bytes } })
    vi.stubGlobal('navigator', { ...navigator, credentials: { get: assert } })
    renderApp('/secrets')
    await userEvent.click(await screen.findByRole('button', { name: 'Add secret' }))
    const dialog = within(await screen.findByRole('dialog', { name: 'Add secret' }))
    await userEvent.type(dialog.getByLabelText(/^Name/), 'DB_URL')
    expect(dialog.queryByText(/Existing grants/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Remove secret DB_URL' })).not.toBeInTheDocument()
    await userEvent.type(dialog.getByLabelText(/^Value/), 'db-password')
    await userEvent.click(screen.getByRole('button', { name: 'Add another secret' }))
    expect(screen.getByLabelText(/^Name 2/)).toHaveFocus()
    await userEvent.type(screen.getByLabelText(/^Name 2/), 'API_KEY')
    await userEvent.type(screen.getByLabelText(/^Value 2/), 'api-token')
    await userEvent.click(screen.getByRole('button', { name: 'Add another secret' }))
    await userEvent.type(screen.getByLabelText(/^Name 3/), 'DISCARDED')
    await userEvent.click(screen.getByRole('button', { name: 'Remove entry 3' }))
    expect(screen.queryByDisplayValue('DISCARDED')).not.toBeInTheDocument()
    expect(screen.getByLabelText(/^Name 2/)).toHaveFocus()
    await userEvent.click(screen.getByRole('button', { name: 'Save secrets' }))
    expect(await screen.findByText('Saved DB_URL, API_KEY.')).toBeVisible()
    expect(assert).toHaveBeenCalledTimes(1)
    expect(api.calls.find(call => call.path === '/api/v1/secrets/entries')?.body).toEqual({ names: ['DB_URL', 'API_KEY'] })
    expect(api.count('POST /api/v1/secrets/entries/entry-123/save')).toBe(1)
    expect(JSON.stringify(api.calls)).not.toMatch(/db-password|api-token/)
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
