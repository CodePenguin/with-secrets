import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { entry, mount, provider, session, signedIn, status, violations } from '../../test/fakeApi'
import { renderApp } from '../../test/render'
import { fromBase64Url, toBase64Url } from '../../lib/passkey'

const bitwardenConfig = '{"serverUrl":"https://vault.bitwarden.com","encryptedConfiguration":"sealed-current"}'
const replacementBitwardenConfig = '{"serverUrl":"https://vault.bitwarden.com","encryptedConfiguration":"sealed-replacement"}'
const bitwardenSeal = 'POST /api/v1/providers/bitwarden/seal'
const instance = provider({ type: 'bitwarden', configuration: bitwardenConfig })
const mounted = mount()
const validate = 'POST /api/v1/providers/validate'
const authorize = 'POST /api/v1/authorizations/inline'
const buildProject = '11111111-1111-4111-8111-111111111111'
const stagingProject = '22222222-2222-4222-8222-222222222222'
const buildToken = buildProject + '/S_99999999999949999999999999999999'
const stagingToken = stagingProject + '/S_88888888888848888888888888888888'

function providerApi() {
  return signedIn({
    'GET /api/v1/status': { body: status({ capabilities: { providers: true } }) },
    'GET /api/v1/session': { body: session({ capabilities: ['admin.read', 'admin.decide'] }) },
    'GET /api/v1/providers': { body: [instance] },
    'GET /api/v1/providers/types': { body: [{ type: 'bitwarden', adapterVersion: '1.0' }] },
    [bitwardenSeal]: { body: { config: replacementBitwardenConfig } },
    [`POST /api/v1/providers/${instance.id}/mount-options`]: ({ body }) => {
      const parent = (body as { parentPath?: string }).parentPath
      return { body: parent === buildProject ? [{ name: 'Build token', path: buildToken }] :
        parent === stagingProject ? [{ name: 'Staging token', path: stagingToken }] :
          [{ name: 'Build project', path: buildProject }, { name: 'Staging', path: stagingProject }] }
    },
    [`GET /api/v1/providers/${instance.id}/mounts`]: { body: [mounted] },
    [`GET /api/v1/mounts/${mounted.id}/entries`]: { body: [entry()] },
    [`POST /api/v1/mounts/${mounted.id}/refresh`]: { body: { complete: true, added: 1, removed: 0, changed: 0 } },
  })
}

describe('Providers page', () => {
  it('hides provider navigation when the service lacks provider support', async () => {
    const api = signedIn()
    renderApp('/providers')
    expect(await screen.findByText('Provider administration is unavailable in this session.')).toBeVisible()
    expect(within(screen.getByRole('navigation', { name: 'Main' })).queryByRole('link', { name: 'Providers' })).not.toBeInTheDocument()
    expect(api.count('GET /api/v1/providers')).toBe(0)
  })

  it('shows provider health, browses entries, and refreshes the mount without an authorization', async () => {
    const api = providerApi()
    const user = userEvent.setup()
    const { container } = renderApp('/providers')
    const navigation = await screen.findByRole('navigation', { name: 'Main' })
    expect(await within(navigation).findByRole('link', { name: 'Providers' })).toBeVisible()
    expect(await screen.findByText('healthy')).toBeVisible()
    expect(await violations(container)).toEqual([])
    const grid = within(screen.getByRole('table', { name: 'Providers' }))
    expect(grid.getByText('Bitwarden Secrets Manager')).toBeVisible()
    expect(grid.queryByRole('button', { name: /Change configuration/ })).not.toBeInTheDocument()
    await user.click(grid.getByRole('link', { name: new RegExp(instance.name, 'i') }))
    await user.click(await screen.findByRole('button', { name: 'Show entries for team' }))
    expect(await screen.findByText('team/TOKEN')).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Refresh namespace team' }))
    expect(await screen.findByText(/Namespace refreshed\. Added 1/)).toBeVisible()
    expect(api.count(authorize)).toBe(0)
  })

  it('blocks validation errors and includes confirmed warnings in the authorization request', async () => {
    const api = providerApi()
    api.on(validate, { body: { ok: false, issues: [{ message: 'Vault is missing.', severity: 'error', target: null, providerCode: null }] } })
    const user = userEvent.setup()
    const { container } = renderApp('/providers')
    await user.click(await screen.findByRole('button', { name: /^Add provider$/ }))
    const dialog = screen.getByRole('dialog')
    const form = within(dialog)
    await user.type(form.getByLabelText(/Provider name/), 'New vault')
    await user.selectOptions(form.getByLabelText(/Provider type/), 'bitwarden')
    await user.type(form.getByLabelText(/Bitwarden access token/), 'secret-token')
    await user.click(form.getByRole('button', { name: 'Continue' }))
    expect(await form.findByText('Vault is missing.')).toBeVisible()
    // Validation errors are shown as errors (not warnings), and announced as an alert.
    expect(form.getByRole('alert').textContent).toMatch(/^Problem: Fix the validation errors/)
    expect(form.getByRole('button', { name: 'Continue' })).toBeDisabled()
    expect(api.count(authorize)).toBe(0)

    api.on(validate, { body: { ok: true, issues: [{ message: 'Check access.', severity: 'warning', target: null, providerCode: null }] } })
    await user.type(form.getByLabelText(/Provider name/), ' 2')
    await user.click(form.getByRole('button', { name: 'Continue' }))
    expect(await form.findByText('Check access.')).toBeVisible()
    expect(form.getByRole('button', { name: 'Continue' })).toBeDisabled()
    expect(await violations(container)).toEqual([])
    await user.click(form.getByRole('checkbox', { name: 'Continue with these warnings' }))
    await user.click(form.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(api.count(authorize)).toBe(1))
    expect(api.calls.find((call) => call.method + ' ' + call.path === authorize)?.body).toEqual({
      operation: 'provider-add',
      parameters: { name: 'New vault 2', type: 'bitwarden', config: replacementBitwardenConfig, 'max-stale-seconds': '0', 'confirm-warnings': 'yes' },
    })
  })

  it('shows the terminal verification details and asks for a passkey only after values are staged', async () => {
    const api = providerApi()
    const user = userEvent.setup()
    const id = 'a29b54c6-ed2e-42c1-be2b-e535142807e3'
    const refresh = { id, state: 'waiting', requestedBy: 'Laptop', providerName: instance.name,
      account: 'Vault@example.test', region: 'lastpass.com', expires: '2026-11-25T19:10:00Z',
      mappings: [{ providerPath: '100/F_70617373776F7264', localName: 'APP_PASSWORD' }] }
    const launch = `POST /api/v1/providers/${instance.id}/value-refreshes`
    const get = `GET /api/v1/provider-value-refreshes/${id}`
    api.on('GET /api/v1/providers', { body: [{ ...instance, type: 'lastpass-refresh', actions: ['refresh-values'] }] })
    api.on(launch, async ({ body }) => {
      const browserKey = await crypto.subtle.importKey('spki', fromBase64Url(String(body?.browserKey)),
        { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt'])
      const encrypted = await crypto.subtle.encrypt('RSA-OAEP', browserKey, new TextEncoder().encode('A7BW'))
      return { status: 201, body: { refresh, encryptedCode: toBase64Url(new Uint8Array(encrypted)) } }
    })
    api.on(get, { body: refresh })
    renderApp(`/providers/${instance.id}`)
    await user.click(await screen.findByRole('button', { name: `Refresh values for ${instance.name}` }))
    const dialog = within(screen.getByRole('dialog'))
    expect(await dialog.findByText('A7BW', {}, { timeout: 3000 })).toBeVisible()
    expect(dialog.getByText('Vault@example.test')).toBeVisible()
    expect(dialog.getByText('Item 100 / password →', { exact: false })).toBeVisible()
    expect(dialog.getByText('APP_PASSWORD')).toBeVisible()
    expect(dialog.queryByRole('textbox')).not.toBeInTheDocument()
    expect(dialog.queryByRole('button', { name: 'Review and approve' })).not.toBeInTheDocument()
    expect(api.count(authorize)).toBe(0)
    api.on(get, { body: { ...refresh, state: 'ready' } })
    await user.click(await dialog.findByRole('button', { name: 'Review and approve' }, { timeout: 3000 }))
    await waitFor(() => expect(api.count(authorize)).toBe(1))
    expect(api.calls.find((call) => call.method + ' ' + call.path === authorize)?.body).toEqual({
      operation: 'provider-refresh-values', parameters: { id },
    })
    expect(api.calls.find((call) => call.method + ' ' + call.path === launch)?.body).toEqual({ browserKey: expect.any(String) })
  })

  it('configures LastPass with an email and region and hides cache freshness', async () => {
    const api = providerApi()
    const config = '{"username":"Vault@example.test","european":true}'
    api.on('GET /api/v1/providers/types', { body: [{ type: 'lastpass-refresh', adapterVersion: '1' }] })
    api.on(validate, { body: { ok: true, issues: [] } })
    const user = userEvent.setup()
    renderApp('/providers')
    await user.click(await screen.findByRole('button', { name: /^Add provider$/ }))
    const form = within(screen.getByRole('dialog'))
    await user.type(form.getByLabelText(/Provider name/), 'Team vault')
    await user.selectOptions(form.getByLabelText(/Provider type/), 'lastpass-refresh')
    await user.type(form.getByLabelText(/LastPass account email/), 'Vault@example.test')
    await user.selectOptions(form.getByLabelText(/LastPass region/), 'eu')
    expect(form.queryByRole('group', { name: 'Cache freshness' })).not.toBeInTheDocument()
    expect(form.queryByLabelText(/master password/)).not.toBeInTheDocument()
    await user.click(form.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(api.count(authorize)).toBe(1))
    expect(api.calls.find((call) => call.method + ' ' + call.path === authorize)?.body).toMatchObject({
      operation: 'provider-add',
      parameters: { config, type: 'lastpass-refresh' },
    })
    expect(api.calls.find((call) => call.method + ' ' + call.path === authorize)?.body?.parameters).not.toHaveProperty('max-stale-seconds')
  })

  it.each([
    ['onepassword', 'add', /service-account token/],
    ['onepassword', 'replace', /service-account token/],
    ['vault', 'add', /Vault token/],
    ['vault', 'replace', /Vault token/],
  ] as const)('seals the %s token before the %s authorization', async (type, mode, tokenLabel) => {
    const api = providerApi()
    const seal = `POST /api/v1/providers/${type}/seal`
    const config = '{"encryptedConfiguration":"encrypted:fixture"}'
    const token = 'ops_test_token'
    const existing = { ...instance, type, configuration: '{"encryptedConfiguration":"encrypted:current-fixture"}', actions: ['config'] }
    api.on('GET /api/v1/providers', { body: [existing] })
    api.on('GET /api/v1/providers/types', { body: [{ type: 'test', adapterVersion: '1.0' }, { type, adapterVersion: '1.0' }] })
    api.on(seal, { body: { config } })
    api.on(validate, { body: { ok: true, issues: [{ message: 'Check vault access.', severity: 'warning' }] } })
    const user = userEvent.setup()
    renderApp(mode === 'add' ? '/providers' : `/providers/${instance.id}`)
    await user.click(await screen.findByRole('button', { name: mode === 'add' ? /^Add provider$/ : `Change configuration ${instance.name}` }))
    const form = within(screen.getByRole('dialog'))
    if (mode === 'add') {
      await user.type(form.getByLabelText(/Provider name/), 'Team vault')
      await user.selectOptions(form.getByLabelText(/Provider type/), type)
    }
    expect(form.queryByLabelText(/Configuration JSON/)).not.toBeInTheDocument()
    const input = form.getByLabelText(tokenLabel)
    expect(input).toHaveAttribute('type', 'password')
    expect(input).toHaveValue('')
    await user.type(input, token)
    await user.click(form.getByRole('button', { name: 'Continue' }))
    expect(await form.findByText('Check vault access.')).toBeVisible()
    expect(input).toHaveValue('')
    await user.click(form.getByRole('checkbox', { name: 'Continue with these warnings' }))
    await user.click(form.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(api.count(authorize)).toBe(1))
    expect(api.count(seal)).toBe(1)
    expect(api.calls.filter((call) => JSON.stringify(call.body)?.includes(token)).map((call) => call.method + ' ' + call.path)).toEqual([seal])
    expect(api.calls.find((call) => call.method + ' ' + call.path === authorize)?.body).toMatchObject({
      operation: mode === 'add' ? 'provider-add' : 'provider-config',
      parameters: { config, 'confirm-warnings': 'yes' },
    })
  })


  it('shows the provider link in the navigation only when the service offers providers', async () => {
    const reader = { 'GET /api/v1/session': { body: session({ capabilities: ['admin.read'] }) } }
    signedIn({ ...reader, 'GET /api/v1/status': { body: status({ capabilities: { providers: true } }) } })
    const { unmount } = renderApp('/machines')
    expect(await within(await screen.findByRole('navigation', { name: 'Main' })).findByRole('link', { name: 'Providers' })).toBeVisible()
    unmount()

    const api = signedIn({ ...reader, 'GET /api/v1/status': { body: status({ capabilities: { providers: false } }) } })
    renderApp('/machines')
    const navigation = await screen.findByRole('navigation', { name: 'Main' })
    expect(await within(navigation).findByRole('link', { name: 'Machines' })).toBeVisible()
    await waitFor(() => expect(api.count('GET /api/v1/status')).toBeGreaterThan(0))
    await waitFor(() => expect(api.count('GET /api/v1/session')).toBeGreaterThan(0))
    expect(within(navigation).queryByRole('link', { name: 'Providers' })).not.toBeInTheDocument()
  })

  it('sets up Bitwarden through the provider validation and passkey approval flow', async () => {
    const api = providerApi()
    api.on('GET /api/v1/providers/types', { body: [{ type: 'onepassword', adapterVersion: '1.0' }, { type: 'bitwarden', adapterVersion: '1.0' }] })
    api.on(validate, { body: { ok: true, issues: [] } })
    const user = userEvent.setup()
    renderApp('/providers')
    await user.click(await screen.findByRole('button', { name: /^Add provider$/ }))
    const form = within(screen.getByRole('dialog'))
    expect(form.queryByLabelText(/Configuration JSON/)).not.toBeInTheDocument()
    await user.selectOptions(form.getByLabelText(/Provider type/), 'onepassword')
    expect(form.getByLabelText(/service-account token/)).toBeVisible()
    await user.selectOptions(form.getByLabelText(/Provider type/), 'bitwarden')
    expect(form.queryByLabelText(/service-account token/)).not.toBeInTheDocument()
    expect(form.getByLabelText(/Bitwarden access token/)).toHaveAttribute('type', 'password')
    expect(form.getByLabelText(/Server URL/)).toHaveValue('https://vault.bitwarden.com')
    await user.type(form.getByLabelText(/Provider name/), 'Team Bitwarden')
    await user.type(form.getByLabelText(/Bitwarden access token/), 'secret-token')
    await user.click(form.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(api.count(authorize)).toBe(1))
    const config = replacementBitwardenConfig
    expect(api.calls.filter(call => JSON.stringify(call.body)?.includes('secret-token')).map(call => call.method + ' ' + call.path)).toEqual([bitwardenSeal])
    expect(api.calls.find((call) => call.method + ' ' + call.path === validate)?.body).toEqual({ type: 'bitwarden', config })
    expect(api.calls.find((call) => call.method + ' ' + call.path === authorize)?.body).toEqual({
      operation: 'provider-add',
      parameters: { name: 'Team Bitwarden', type: 'bitwarden', config, 'max-stale-seconds': '0' },
    })
  })

  it('shows empty states for no providers and no mounts', async () => {
    const api = providerApi()
    api.on('GET /api/v1/providers', { body: [] })
    const { unmount } = renderApp('/providers')
    expect(await screen.findByText('No provider instances configured.')).toBeVisible()
    unmount()

    const detail = providerApi()
    detail.on(`GET /api/v1/providers/${instance.id}/mounts`, { body: [] })
    const { container } = renderApp(`/providers/${instance.id}`)
    expect(await screen.findByText('No mounts configured.')).toBeVisible()
    expect(await violations(container)).toEqual([])
  })

  describe('signs exactly the parameters each dialog shows', () => {
    const full = { ...instance, actions: ['config', 'max-stale', 'remove', 'add-mount'] }

    async function signed(open: string, fill: (form: ReturnType<typeof within>, user: ReturnType<typeof userEvent.setup>) => Promise<void>, page = `/providers/${full.id}`) {
      const api = providerApi()
      api.on('GET /api/v1/providers', { body: [full] })
      api.on(validate, { body: { ok: true, issues: [] } })
      const user = userEvent.setup()
      renderApp(page)
      await user.click(await screen.findByRole('button', { name: open }))
      const dialog = await screen.findByRole('dialog')
      expect(await violations(dialog)).toEqual([])
      await fill(within(dialog), user)
      // A dialog with fields asks for them first; one without asks the service for the authorization as it opens.
      const proceed = within(dialog).queryByRole('button', { name: 'Continue' })
      if (proceed) await user.click(proceed)
      await waitFor(() => expect(api.count(authorize)).toBe(1))

      return api.calls.find((call) => call.method + ' ' + call.path === authorize)?.body
    }

    it('change configuration', async () => {
      const body = await signed(`Change configuration ${full.name}`, async (form, user) => {
        expect(form.queryByLabelText(/Provider type/)).not.toBeInTheDocument()
        expect(form.getByText('Bitwarden Secrets Manager')).toBeVisible()
        await user.type(form.getByLabelText(/Bitwarden access token/), 'new-credential')
        const freshness = within(form.getByRole('group', { name: 'Cache freshness' }))
        expect(freshness.queryByLabelText(/Seconds/)).not.toBeInTheDocument()
        const minutes = freshness.getByLabelText(/Minutes/)
        await user.clear(minutes)
        await user.type(minutes, '30')
      })
      expect(body).toEqual({ operation: 'provider-config', parameters: { id: full.id, revision: '2', config: replacementBitwardenConfig, 'max-stale-seconds': '5400' } })
    })

    it('changes only cache freshness without replacing the credential', async () => {
      const body = await signed(`Change configuration ${full.name}`, async (form, user) => {
        const minutes = form.getByLabelText(/Minutes/)
        await user.clear(minutes)
        await user.type(minutes, '15')
      })
      expect(body).toEqual({ operation: 'provider-config', parameters: { id: full.id, revision: '2', config: bitwardenConfig, 'max-stale-seconds': '4500' } })
    })

    it('remove provider', async () => {
      const body = await signed(`Remove provider ${full.name}`, async () => undefined)
      expect(body).toEqual({ operation: 'provider-remove', parameters: { id: full.id, revision: '2' } })
    })

    it('mounts a Bitwarden secret by name and clears the selection when the project changes', async () => {
      const body = await signed(`Add mount ${full.name}`, async (form, user) => {
        await user.selectOptions(form.getByLabelText(/Mount kind/), 'single')
        await user.type(form.getByLabelText(/Logical path/), 'ops/TOKEN')
        expect(form.queryByLabelText(/Provider path/)).not.toBeInTheDocument()
        const project = form.getByLabelText(/^Project/)
        await form.findByRole('option', { name: 'Build project' })
        await user.selectOptions(project, 'Build project')
        await form.findByRole('option', { name: 'Build token' })
        const secret = form.getByLabelText(/^Secret/)
        await user.selectOptions(secret, 'Build token')
        await user.selectOptions(project, 'Staging')
        await form.findByRole('option', { name: 'Staging token' })
        expect(secret).toHaveValue('')
        await user.selectOptions(secret, 'Staging token')
      })
      expect(body).toEqual({ operation: 'mount-add', parameters: { instance: full.id, kind: 'single', path: 'ops/TOKEN', base: stagingToken } })
    })

    it('remove mount', async () => {
      const body = await signed(`Remove mount ${mounted.logicalPath}`, async () => undefined)
      expect(body).toEqual({ operation: 'mount-remove', parameters: { id: mounted.id } })
    })
  })
})
