import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { entry, mount, provider, session, signedIn, status, violations } from '../../test/fakeApi'
import { renderApp } from '../../test/render'

const instance = provider()
const mounted = mount()
const validate = 'POST /api/v1/providers/validate'
const authorize = 'POST /api/v1/authorizations/inline'

function providerApi() {
  return signedIn({
    'GET /api/v1/status': { body: status({ capabilities: { providers: true } }) },
    'GET /api/v1/session': { body: session({ capabilities: ['admin.read', 'admin.decide'] }) },
    'GET /api/v1/providers': { body: [instance] },
    'GET /api/v1/providers/types': { body: [{ type: 'test', adapterVersion: '1.0' }] },
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
    await user.click(screen.getByRole('link', { name: instance.name }))
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
    expect(form.getByText(/Do not put passwords or tokens/)).toBeVisible()
    await user.type(form.getByLabelText(/Provider name/), 'New vault')
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
      parameters: { name: 'New vault 2', type: 'test', config: '{}', 'max-stale-seconds': '3600', 'confirm-warnings': 'yes' },
    })
  })

  it.each(['add', 'replace'] as const)('seals the LastPass master password before the %s authorization', async (mode) => {
    const api = providerApi()
    const seal = 'POST /api/v1/providers/lastpass/seal'
    const config = '{"username":"user@example.test","encryptedConfiguration":"encrypted:fixture"}'
    const masterPassword = 'lp_test_password'
    const existing = { ...instance, type: 'lastpass', configuration: config, actions: ['config'] }
    api.on('GET /api/v1/providers', { body: [existing] })
    api.on('GET /api/v1/providers/types', { body: [{ type: 'test', adapterVersion: '1.0' }, { type: 'lastpass', adapterVersion: '1.0' }] })
    api.on(seal, { body: { config } })
    api.on(validate, { body: { ok: true, issues: [{ message: 'Check vault access.', severity: 'warning' }] } })
    const user = userEvent.setup()
    renderApp(mode === 'add' ? '/providers' : `/providers/${instance.id}`)
    await user.click(await screen.findByRole('button', { name: mode === 'add' ? /^Add provider$/ : `Change configuration ${instance.name}` }))
    const form = within(screen.getByRole('dialog'))
    if (mode === 'add') {
      await user.type(form.getByLabelText(/Provider name/), 'Team vault')
      await user.selectOptions(form.getByLabelText(/Provider type/), 'lastpass')
      await user.type(form.getByLabelText(/LastPass username/), 'user@example.test')
    }
    expect(form.queryByLabelText(/Configuration JSON/)).not.toBeInTheDocument()
    const input = form.getByLabelText(/master password/)
    expect(input).toHaveAttribute('type', 'password')
    expect(input).toHaveValue('')
    await user.type(input, masterPassword)
    await user.click(form.getByRole('button', { name: 'Continue' }))
    expect(await form.findByText('Check vault access.')).toBeVisible()
    expect(input).toHaveValue('')
    await user.click(form.getByRole('checkbox', { name: 'Continue with these warnings' }))
    await user.click(form.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(api.count(authorize)).toBe(1))
    expect(api.count(seal)).toBe(1)
    expect(api.calls.filter((call) => JSON.stringify(call.body)?.includes(masterPassword)).map((call) => call.method + ' ' + call.path)).toEqual([seal])
    expect(api.calls.find((call) => call.method + ' ' + call.path === authorize)?.body).toMatchObject({
      operation: mode === 'add' ? 'provider-add' : 'provider-config',
      parameters: { config, 'confirm-warnings': 'yes' },
    })
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
    const existing = { ...instance, type, configuration: config, actions: ['config'] }
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
    api.on('GET /api/v1/providers/types', { body: [{ type: 'test', adapterVersion: '1.0' }, { type: 'bitwarden', adapterVersion: '1.0' }] })
    api.on(validate, { body: { ok: true, issues: [] } })
    const user = userEvent.setup()
    renderApp('/providers')
    await user.click(await screen.findByRole('button', { name: /^Add provider$/ }))
    const form = within(screen.getByRole('dialog'))
    expect(form.getByLabelText(/Configuration JSON/)).toBeVisible()
    await user.selectOptions(form.getByLabelText(/Provider type/), 'bitwarden')
    expect(form.queryByLabelText(/Configuration JSON/)).not.toBeInTheDocument()
    expect(form.getByLabelText(/Access token variable/)).toHaveValue('BWS_ACCESS_TOKEN')
    expect(form.getByLabelText(/Server URL/)).toHaveValue('https://vault.bitwarden.com')
    await user.type(form.getByLabelText(/Provider name/), 'Team Bitwarden')
    await user.click(form.getByRole('button', { name: 'Continue' }))
    await waitFor(() => expect(api.count(authorize)).toBe(1))
    const config = '{"tokenEnv":"BWS_ACCESS_TOKEN","serverUrl":"https://vault.bitwarden.com"}'
    expect(api.calls.find((call) => call.method + ' ' + call.path === validate)?.body).toEqual({ type: 'bitwarden', config })
    expect(api.calls.find((call) => call.method + ' ' + call.path === authorize)?.body).toEqual({
      operation: 'provider-add',
      parameters: { name: 'Team Bitwarden', type: 'bitwarden', config, 'max-stale-seconds': '3600' },
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
    const full = provider({ actions: ['config', 'max-stale', 'remove', 'add-mount'] })

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
        const config = form.getByLabelText(/Configuration JSON/)
        await user.clear(config)
        await user.type(config, '{{ "label": "new build" }')
      })
      expect(body).toEqual({ operation: 'provider-config', parameters: { id: full.id, revision: '2', config: '{"label":"new build"}' } })
    })

    it('change maximum staleness', async () => {
      const body = await signed(`Change maximum staleness ${full.name}`, async (form, user) => {
        const seconds = form.getByLabelText(/Seconds/)
        await user.clear(seconds)
        await user.type(seconds, '30')
      })
      expect(body).toEqual({ operation: 'provider-max-stale', parameters: { id: full.id, revision: '2', 'max-stale-seconds': '3630' } })
    })

    it('remove provider', async () => {
      const body = await signed(`Remove provider ${full.name}`, async () => undefined, '/providers')
      expect(body).toEqual({ operation: 'provider-remove', parameters: { id: full.id, revision: '2' } })
    })

    it('add mount', async () => {
      const body = await signed(`Add mount ${full.name}`, async (form, user) => {
        await user.selectOptions(form.getByLabelText(/Mount kind/), 'single')
        await user.type(form.getByLabelText(/Logical path/), 'ops/TOKEN')
        await user.type(form.getByLabelText(/Provider path/), 'kv/ops/token')
      })
      expect(body).toEqual({ operation: 'mount-add', parameters: { instance: full.id, kind: 'single', path: 'ops/TOKEN', base: 'kv/ops/token' } })
    })

    it('remove mount', async () => {
      const body = await signed(`Remove mount ${mounted.logicalPath}`, async () => undefined)
      expect(body).toEqual({ operation: 'mount-remove', parameters: { id: mounted.id } })
    })
  })
})
