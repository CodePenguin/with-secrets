import { api } from '../../api/client'
import type { Mount, Provider, ProviderType } from '../../api/types'
import type { FieldDef, FormValues, OperationDef, Prepared } from '../authorization/operations'

const maxConfig = 2_000
const durationFields: FieldDef[] = [
  { name: 'hours', label: 'Hours', kind: 'number' },
  { name: 'minutes', label: 'Minutes', kind: 'number' },
]
const cacheFreshness = {
  label: 'Cache freshness',
  hint: 'Set how long cached values can be used, up to 24 hours. Set both fields to zero to fetch fresh values every time.',
  fields: durationFields,
}

function text(values: FormValues, field: string): string {
  return String(values[field] ?? '').trim()
}

function durationValues(seconds: number): FormValues {
  const minutes = Math.ceil(seconds / 60)
  return { hours: String(Math.floor(minutes / 60)), minutes: String(minutes % 60) }
}

function maxStale(values: FormValues, errors: Record<string, string>, previous = 0): string {
  const hours = text(values, 'hours') || '0'
  const minutes = text(values, 'minutes') || '0'
  const duration = Number(hours) * 3600 + Number(minutes) * 60
  if (!/^\d{1,2}$/.test(hours) || duration > 86400) errors.hours = 'Enter a duration of at most 24 hours.'
  if (!/^\d{1,2}$/.test(minutes) || Number(minutes) > 59) errors.minutes = 'Enter minutes from 0 to 59.'

  return String(duration === Math.ceil(previous / 60) * 60 ? previous : duration)
}

const onePassword = 'onepassword'
const bitwarden = 'bitwarden'
export const lastPassRefresh = 'lastpass-refresh'
export const lastPassFields: Record<string, string> = {
  F_70617373776F7264: 'password',
  F_757365726E616D65: 'username',
  F_6E6F7465: 'note',
  F_75726C: 'url',
}
const vault = 'vault'
const tokenField: FieldDef = { name: 'serviceAccountToken', label: '1Password service-account token', kind: 'password', maxLength: maxConfig }
const vaultTokenField: FieldDef = { name: 'vaultToken', label: 'Vault token', kind: 'password', maxLength: maxConfig }
const lastPassUsernameField: FieldDef = { name: 'lastPassUsername', label: 'LastPass account email', kind: 'text', maxLength: 256 }
const lastPassRegionField: FieldDef = { name: 'lastPassRegion', label: 'LastPass region', kind: 'select',
  options: [{ value: 'us', label: 'lastpass.com' }, { value: 'eu', label: 'lastpass.eu' }] }
const bitwardenDefaults = { serverUrl: 'https://vault.bitwarden.com' }
const bitwardenToken: FieldDef = { name: 'bitwardenToken', label: 'Bitwarden access token', kind: 'password', maxLength: 1024 }
const bitwardenFields: FieldDef[] = [
  bitwardenToken,
  { name: 'serverUrl', label: 'Server URL', kind: 'text', required: true, maxLength: 512 },
]

const providerForms = new Map<string, { label: string; fields: FieldDef[] }>([
  [bitwarden, { label: 'Bitwarden Secrets Manager', fields: bitwardenFields }],
  [onePassword, { label: '1Password', fields: [tokenField] }],
  [vault, { label: 'HashiCorp Vault', fields: [vaultTokenField] }],
  [lastPassRefresh, { label: 'LastPass', fields: [lastPassUsernameField, lastPassRegionField] }],
])

export function hasProviderForm(type: string): boolean {
  return providerForms.has(type)
}

export function providerTypeLabel(type: string): string {
  return providerForms.get(type)?.label ?? type
}

function initialConfiguration(provider: Provider): FormValues {
  if (provider.type === onePassword || provider.type === vault) return { savedConfiguration: provider.configuration }
  if (provider.type === lastPassRefresh) {
    try {
      const config = JSON.parse(provider.configuration) as { username?: unknown; european?: unknown } | null
      return {
        lastPassUsername: typeof config?.username === 'string' ? config.username : '',
        lastPassRegion: config?.european === true ? 'eu' : 'us',
      }
    } catch {
      return { lastPassUsername: '', lastPassRegion: 'us' }
    }
  }
  if (provider.type !== bitwarden) return {}

  try {
    const config = JSON.parse(provider.configuration) as { serverUrl?: unknown; encryptedConfiguration?: unknown } | null
    const serverUrl = typeof config?.serverUrl === 'string' ? config.serverUrl : bitwardenDefaults.serverUrl
    return typeof config?.encryptedConfiguration === 'string' && config.encryptedConfiguration
      ? { serverUrl, savedServerUrl: serverUrl, savedConfiguration: provider.configuration }
      : { serverUrl }
  } catch {
    return { ...bitwardenDefaults }
  }
}

function bitwardenConfiguration(values: FormValues, errors: Record<string, string>): string {
  const serverUrl = text(values, 'serverUrl')
  try {
    const url = new URL(serverUrl)
    if (!/^https:\/\//i.test(serverUrl) || url.username || url.password || /[?#]/.test(serverUrl)) throw new Error()
  } catch {
    errors.serverUrl = 'Enter an HTTPS URL without credentials, a query, or a fragment.'
  }
  if (text(values, bitwardenToken.name)) return '{}'
  if (serverUrl === text(values, 'sealedBitwardenServer')) return text(values, 'sealedBitwardenConfiguration')
  if (serverUrl === text(values, 'savedServerUrl')) return text(values, 'savedConfiguration')
  errors.bitwardenToken = text(values, 'savedConfiguration') ? 'Enter a token for the new server URL.' : 'Enter a Bitwarden access token.'
  return ''
}

function providerConfiguration(type: string, values: FormValues, errors: Record<string, string>): string {
  if (type === bitwarden) return bitwardenConfiguration(values, errors)
  if (type === onePassword) {
    if (text(values, tokenField.name)) return '{}'
    const sealed = text(values, 'sealedConfiguration') || text(values, 'savedConfiguration')
    if (!sealed) errors.serviceAccountToken = 'Enter a 1Password service-account token.'
    return sealed
  }
  if (type === vault) {
    if (text(values, vaultTokenField.name)) return '{}'
    const sealed = text(values, 'sealedVaultConfiguration') || text(values, 'savedConfiguration')
    if (!sealed) errors.vaultToken = 'Enter a Vault token.'
    return sealed
  }
  if (type === lastPassRefresh) {
    const username = text(values, lastPassUsernameField.name)
    if (!/^[^@\s]+@[^@\s]+$/.test(username)) errors.lastPassUsername = 'Enter your LastPass account email address.'
    return JSON.stringify({ username, european: text(values, 'lastPassRegion') === 'eu' })
  }
  return ''
}

async function sealOnePassword(prepared: Prepared, values: FormValues, signal: AbortSignal) {
  const token = text(values, tokenField.name)
  if (!token) return { prepared, draft: values }
  const { config } = await api.post('/api/v1/providers/onepassword/seal', { body: { serviceAccountToken: token }, signal })
  return {
    prepared: { ...prepared, parameters: { ...prepared.parameters, config } },
    draft: { ...values, serviceAccountToken: '', sealedConfiguration: config },
  }
}

async function sealVault(prepared: Prepared, values: FormValues, signal: AbortSignal) {
  const token = text(values, vaultTokenField.name)
  if (!token) return { prepared, draft: values }
  const { config } = await api.post('/api/v1/providers/vault/seal', { body: { token }, signal })
  return {
    prepared: { ...prepared, parameters: { ...prepared.parameters, config } },
    draft: { ...values, vaultToken: '', sealedVaultConfiguration: config },
  }
}

async function sealBitwarden(prepared: Prepared, values: FormValues, signal: AbortSignal) {
  const token = text(values, bitwardenToken.name)
  if (!token) return { prepared, draft: values }
  const serverUrl = text(values, 'serverUrl')
  const { config } = await api.post('/api/v1/providers/bitwarden/seal', { body: { token, serverUrl }, signal })
  return {
    prepared: { ...prepared, parameters: { ...prepared.parameters, config } },
    draft: { ...values, bitwardenToken: '', sealedBitwardenConfiguration: config, sealedBitwardenServer: serverUrl },
  }
}

async function prepareForValidation(prepared: Prepared, values: FormValues, signal: AbortSignal) {
  const type = text(values, 'type')
  if (type === onePassword) return sealOnePassword(prepared, values, signal)
  if (type === vault) return sealVault(prepared, values, signal)
  if (type === bitwarden) return sealBitwarden(prepared, values, signal)
  return { prepared, draft: values }
}


export function addProvider(types: ProviderType[]): OperationDef {
  const available = types.filter(({ type }) => hasProviderForm(type))
  return {
    key: 'provider-add',
    title: 'Add provider',
    confirmLabel: 'Add provider',
    fields: [
      { name: 'name', label: 'Provider name', kind: 'text', required: true, maxLength: 64 },
      { name: 'type', label: 'Provider type', kind: 'select', required: true,
        options: [{ value: '', label: 'Choose a provider type' }, ...available.map(({ type }) => ({ value: type, label: providerTypeLabel(type) }))] },
      ...available.flatMap(({ type }) => (providerForms.get(type)?.fields ?? []).map(
        (field) => ({ ...field, visible: (values: FormValues) => text(values, 'type') === type }),
      )),
    ],
    fieldGroup: { ...cacheFreshness, visible: values => hasProviderForm(text(values, 'type')) && text(values, 'type') !== lastPassRefresh },
    initial: { type: '', lastPassRegion: 'us', ...bitwardenDefaults, ...durationValues(0) },
    prepare(values) {
      const errors: Record<string, string> = {}
      const name = text(values, 'name')
      const type = text(values, 'type')
      if (!name || name.length > 64) errors.name = 'Enter a provider name of 1 to 64 characters.'
      if (!available.some((item) => item.type === type)) errors.type = 'Choose a provider type.'
      const config = providerConfiguration(type, values, errors)
      const parameters: Record<string, string> = { name, type, config }
      if (type !== lastPassRefresh) parameters['max-stale-seconds'] = maxStale(values, errors)
      if (Object.keys(errors).length) return { errors }

      return { operation: 'provider-add', parameters, summary: `Add provider ${name}.`, done: `Added provider ${name}.` }
    },
    prepareForValidation,
    validate: ({ parameters }, signal) => api.post('/api/v1/providers/validate', { body: { type: String(parameters.type), config: String(parameters.config) }, signal }),
  }
}

export function changeProviderConfig(provider: Provider): OperationDef {
  const interactive = provider.type === lastPassRefresh
  return {
    key: 'provider-config',
    title: 'Change configuration',
    confirmLabel: 'Save configuration',
    about: [['Provider', provider.name], ['Type', providerTypeLabel(provider.type)]],
    fields: providerForms.get(provider.type)?.fields.map(field => field.kind === 'password'
      ? { ...field, hint: 'Leave blank to keep the current credential.' } : field),
    fieldGroup: interactive ? undefined : cacheFreshness,
    initial: { ...initialConfiguration(provider), ...durationValues(provider.maxStaleSeconds) },
    prepare(values) {
      const errors: Record<string, string> = {}
      if (!hasProviderForm(provider.type)) return { errors: { type: 'This provider has no configuration form.' } }
      const config = providerConfiguration(provider.type, values, errors)
      const seconds = interactive ? undefined : maxStale(values, errors, provider.maxStaleSeconds)
      const newCredential = [bitwardenToken, tokenField, vaultTokenField].some(field => text(values, field.name))
      if (!newCredential && config === provider.configuration && (seconds === undefined || Number(seconds) === provider.maxStaleSeconds) && !Object.keys(errors).length) {
        errors[interactive ? lastPassUsernameField.name : 'hours'] = 'Change a setting before saving.'
      }
      if (Object.keys(errors).length) return { errors }

      const parameters: Record<string, string> = { id: provider.id, revision: String(provider.revision), config }
      if (seconds !== undefined) parameters['max-stale-seconds'] = seconds
      return { operation: 'provider-config', parameters, summary: `Change configuration for ${provider.name}.`, done: 'Configuration saved.' }
    },
    prepareForValidation: provider.type === onePassword ? sealOnePassword : provider.type === vault ? sealVault : provider.type === bitwarden ? sealBitwarden : undefined,
    validate: ({ parameters }, signal) => parameters.config === provider.configuration
      ? Promise.resolve({ ok: true, issues: [] })
      : api.post('/api/v1/providers/validate', { body: { type: provider.type, config: String(parameters.config) }, signal }),
  }
}

export function changeMaxStale(provider: Provider): OperationDef {
  return {
    key: 'provider-max-stale',
    title: 'Change maximum staleness',
    confirmLabel: 'Save cache policy',
    about: [['Provider', provider.name]],
    fieldGroup: cacheFreshness,
    initial: durationValues(provider.maxStaleSeconds),
    prepare(values) {
      const errors: Record<string, string> = {}
      const seconds = maxStale(values, errors, provider.maxStaleSeconds)
      if (Object.keys(errors).length) return { errors }

      return { operation: 'provider-max-stale', parameters: { id: provider.id, revision: String(provider.revision), 'max-stale-seconds': seconds }, summary: `Change how long cached values from ${provider.name} may be served.`, done: 'Cache policy saved.' }
    },
  }
}

export function removeProvider(provider: Provider): OperationDef {
  return {
    key: 'provider-remove', title: 'Remove provider', confirmLabel: 'Remove provider', danger: true,
    prepare: () => ({
      operation: 'provider-remove', parameters: { id: provider.id, revision: String(provider.revision) },
      summary: `Remove ${provider.name} and delete its cached values.`, done: `Removed provider ${provider.name}.`,
    }),
  }
}

export function addMount(provider: Provider): OperationDef & { fields: FieldDef[] } {
  const interactive = provider.type === lastPassRefresh
  const browseBitwarden = provider.type === bitwarden
  const mountOptions = (parentPath?: string) => ({
    key: ['mount-options', provider.id, provider.revision, parentPath],
    load: async (signal: AbortSignal) => {
      const options = await api.post('/api/v1/providers/{id}/mount-options', {
        path: { id: provider.id }, body: parentPath ? { parentPath } : {}, signal,
      })
      const counts = new Map<string, number>()
      for (const { name } of options) counts.set(name, (counts.get(name) ?? 0) + 1)
      return options.map(({ path, name }) => ({
        value: path, label: counts.get(name) === 1 ? name : `${name} (${path.split('/').at(-1)})`,
      }))
    },
  })

  return {
    key: 'mount-add',
    title: 'Add mount',
    confirmLabel: 'Add mount',
    about: [['Provider', provider.name]],
    fields: interactive ? [
      { name: 'path', label: 'Logical path', kind: 'text', required: true, maxLength: 200 },
      { name: 'itemId', label: 'LastPass item ID', kind: 'text', required: true, maxLength: 32 },
      { name: 'itemField', label: 'LastPass field', kind: 'select',
        options: Object.entries(lastPassFields).map(([value, label]) => ({ value, label })) },
    ] : [
      { name: 'kind', label: 'Mount kind', kind: 'select', options: [{ value: 'tree', label: browseBitwarden ? 'Entire project' : 'Tree' }, { value: 'single', label: 'Single secret' }] },
      ...(browseBitwarden ? [
        { name: 'project', label: 'Project', kind: 'select', required: true, loadOptions: () => mountOptions(), clearOnChange: ['secret'] },
        { name: 'secret', label: 'Secret', kind: 'select', required: true, loadOptions: values => mountOptions(text(values, 'project')),
          visible: values => text(values, 'kind') === 'single' && !!text(values, 'project') },
      ] satisfies FieldDef[] : []),
      { name: 'path', label: 'Logical path', kind: 'text', required: true, maxLength: 200 },
      ...(!browseBitwarden ? [{ name: 'base', label: 'Provider path', kind: 'text', maxLength: 300, hint: provider.type === vault
          ? 'Use a document path for its fields, end a folder path with /, or leave it blank for the KV mount root. For a single secret, use document/field.'
          : 'For a tree mount, leave blank to use the provider root.' }] satisfies FieldDef[] : []),
    ],
    initial: interactive ? { kind: 'single', itemField: 'F_70617373776F7264' } : { kind: 'tree' },
    prepare(values) {
      const errors: Record<string, string> = {}
      const kind = interactive ? 'single' : text(values, 'kind')
      const path = text(values, 'path')
      const id = text(values, 'itemId')
      const field = text(values, 'itemField')
      let base = interactive ? `${id}/${field}` : text(values, 'base')
      if (browseBitwarden) {
        const project = text(values, 'project')
        const secret = text(values, 'secret')
        base = kind === 'single' ? secret : project
        if (!project) errors.project = 'Choose a Bitwarden project.'
        else if (kind === 'single' && !secret.startsWith(project + '/')) errors.secret = 'Choose a secret from this project.'
      }
      if (interactive && !/^[1-9][0-9]{0,31}$/.test(id)) errors.itemId = 'Enter the numeric LastPass item ID.'
      if (interactive && !Object.hasOwn(lastPassFields, field)) errors.itemField = 'Choose a LastPass field.'
      if (kind !== 'tree' && kind !== 'single') errors.kind = 'Choose a mount kind.'
      if (!path || path.length > 200) errors.path = 'Enter a logical path of 1 to 200 characters.'
      if (!browseBitwarden && kind === 'single' && !base) errors.base = 'Enter the provider path to the secret.'
      if (Object.keys(errors).length) return { errors }

      return { operation: 'mount-add', parameters: { instance: provider.id, kind, path, base }, summary: `Mount ${provider.name} at ${path}.`, done: `Added mount ${path}.` }
    },
    validate: validateMount,
  }
}

const validateMount: NonNullable<OperationDef['validate']> = ({ parameters }, signal) =>
  api.post('/api/v1/providers/validate', { body: {
    instance: String(parameters.instance),
    mountBase: String(parameters.base),
    mountKind: parameters.kind === 'single' ? 'single' : 'tree',
  }, signal })

export function mountFromSecrets(providers: readonly Provider[], folders: readonly string[]): OperationDef {
  const mounts = new Map(providers.map(provider => [provider.id, addMount(provider)]))
  const providerField: FieldDef = {
    name: 'provider', label: 'Provider', kind: 'select', required: true,
    options: [{ value: '', label: 'Choose a provider' }, ...providers.map(provider => ({ value: provider.id, label: provider.name }))],
    clearOnChange: ['project', 'secret', 'base', 'itemId'],
  }
  return {
    key: 'mount-add',
    title: 'Mount provider',
    confirmLabel: 'Add mount',
    initial: { provider: providers.length === 1 ? providers[0]!.id : '', kind: 'tree', itemField: 'F_70617373776F7264' },
    fields: values => [
      providerField,
      ...(mounts.get(text(values, 'provider'))?.fields.map(field => field.name === 'path' && folders.length
        ? { ...field, hint: 'Use an existing folder as a starting point, or enter a new path.', suggestions: folders }
        : field) ?? []),
    ],
    prepare: values => mounts.get(text(values, 'provider'))?.prepare(values) ?? { errors: { provider: 'Choose a provider.' } },
    validate: validateMount,
  }
}

export function removeMount(mount: Mount): OperationDef {
  return {
    key: 'mount-remove', title: 'Remove mount', confirmLabel: 'Remove mount', danger: true,
    prepare: () => ({
      operation: 'mount-remove', parameters: { id: mount.id },
      summary: `Remove ${mount.logicalPath} and end any grants whose source changes.`, done: `Removed mount ${mount.logicalPath}.`,
    }),
  }
}
