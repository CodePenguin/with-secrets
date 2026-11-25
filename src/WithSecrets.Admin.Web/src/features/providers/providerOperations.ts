import { api } from '../../api/client'
import type { Mount, Provider, ProviderType } from '../../api/types'
import type { FieldDef, FormValues, OperationDef, Prepared } from '../authorization/operations'

const credentialNotice = 'Do not put passwords or tokens in the configuration. Use the dedicated token field when available.'
const maxConfig = 2_000
const durationFields: FieldDef[] = [
  { name: 'hours', label: 'Hours', kind: 'number', hint: 'Leave the duration at zero for live retrieval. A duration up to 24 hours enables encrypted caching on the authority and fallback during provider outages.' },
  { name: 'minutes', label: 'Minutes', kind: 'number' },
  { name: 'seconds', label: 'Seconds', kind: 'number' },
]

function text(values: FormValues, field: string): string {
  return String(values[field] ?? '').trim()
}

function durationValues(seconds: number): FormValues {
  return { hours: String(Math.floor(seconds / 3600)), minutes: String(Math.floor(seconds / 60) % 60), seconds: String(seconds % 60) }
}

function maxStale(values: FormValues, errors: Record<string, string>): string {
  const hours = text(values, 'hours') || '0'
  const minutes = text(values, 'minutes') || '0'
  const seconds = text(values, 'seconds') || '0'
  const duration = Number(hours) * 3600 + Number(minutes) * 60 + Number(seconds)
  if (!/^\d{1,2}$/.test(hours) || duration > 86400) errors.hours = 'Enter a duration of at most 24 hours.'
  if (!/^\d{1,2}$/.test(minutes) || Number(minutes) > 59) errors.minutes = 'Enter minutes from 0 to 59.'
  if (!/^\d{1,2}$/.test(seconds) || Number(seconds) > 59) errors.seconds = 'Enter seconds from 0 to 59.'

  return String(duration)
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
const jsonField: FieldDef = { name: 'config', label: 'Configuration JSON', kind: 'textarea', maxLength: maxConfig }
const bitwardenDefaults = { tokenEnv: 'BWS_ACCESS_TOKEN', serverUrl: 'https://vault.bitwarden.com' }
const bitwardenFields: FieldDef[] = [
  { name: 'tokenEnv', label: 'Access token variable', kind: 'text', required: true, maxLength: 64,
    hint: 'Enter the name of the variable on the authority service. Use BWS_ACCESS_TOKEN or a name beginning with WITH_SECRETS_BITWARDEN_TOKEN_.' },
  { name: 'serverUrl', label: 'Server URL', kind: 'text', required: true, maxLength: maxConfig,
    hint: 'For a server other than Bitwarden US, set the matching <token variable>_SERVER_URL in the authority service environment.' },
]

function initialConfiguration(provider: Provider): FormValues {
  if (provider.type === onePassword || provider.type === vault) return {}
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
  if (provider.type !== bitwarden) return { config: provider.configuration }

  try {
    const config = JSON.parse(provider.configuration) as { tokenEnv?: unknown; serverUrl?: unknown } | null
    return {
      tokenEnv: typeof config?.tokenEnv === 'string' ? config.tokenEnv : bitwardenDefaults.tokenEnv,
      serverUrl: typeof config?.serverUrl === 'string' ? config.serverUrl : bitwardenDefaults.serverUrl,
    }
  } catch {
    return { ...bitwardenDefaults }
  }
}

function bitwardenConfiguration(values: FormValues, errors: Record<string, string>): string {
  const tokenEnv = text(values, 'tokenEnv')
  const serverUrl = text(values, 'serverUrl')
  if (tokenEnv !== bitwardenDefaults.tokenEnv
    && (!/^WITH_SECRETS_BITWARDEN_TOKEN_[A-Z0-9_]+$/.test(tokenEnv) || tokenEnv.length > 64 || tokenEnv.endsWith('_SERVER_URL'))) {
    errors.tokenEnv = 'Enter a Bitwarden access token variable name.'
  }
  try {
    const url = new URL(serverUrl)
    if (!/^https:\/\//i.test(serverUrl) || url.username || url.password || /[?#]/.test(serverUrl)) throw new Error()
  } catch {
    errors.serverUrl = 'Enter an HTTPS URL without credentials, a query, or a fragment.'
  }
  const config = JSON.stringify({ tokenEnv, serverUrl })
  if (config.length > maxConfig) errors.serverUrl = 'Use a shorter server URL.'
  return config
}

function providerConfiguration(type: string, values: FormValues, errors: Record<string, string>): string {
  if (type === bitwarden) return bitwardenConfiguration(values, errors)
  if (type === onePassword) {
    if (text(values, tokenField.name)) return '{}'
    const sealed = text(values, 'sealedConfiguration')
    if (!sealed) errors.serviceAccountToken = 'Enter a 1Password service-account token.'
    return sealed
  }
  if (type === vault) {
    if (text(values, vaultTokenField.name)) return '{}'
    const sealed = text(values, 'sealedVaultConfiguration')
    if (!sealed) errors.vaultToken = 'Enter a Vault token.'
    return sealed
  }
  if (type === lastPassRefresh) {
    const username = text(values, lastPassUsernameField.name)
    if (!/^[^@\s]+@[^@\s]+$/.test(username)) errors.lastPassUsername = 'Enter your LastPass account email address.'
    return JSON.stringify({ username, european: text(values, 'lastPassRegion') === 'eu' })
  }
  return configuration(values, errors)
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

async function prepareForValidation(prepared: Prepared, values: FormValues, signal: AbortSignal) {
  const type = text(values, 'type')
  if (type === onePassword) return sealOnePassword(prepared, values, signal)
  if (type === vault) return sealVault(prepared, values, signal)
  return { prepared, draft: values }
}


function configuration(values: FormValues, errors: Record<string, string>): string {
  const raw = text(values, 'config')
  try {
    const parsed: unknown = JSON.parse(raw)
    if (parsed === null || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error()
  } catch {
    errors.config = 'Enter a JSON object.'
    return raw
  }

  // Keep JSON string contents and number spellings intact when removing formatting whitespace.
  const compact = raw.replace(/"(?:[^"\\]|\\.)*"|[ \t\r\n]+/gu, (part) => part.startsWith('"') ? part : '')
  if (compact.length > maxConfig) errors.config = 'Use at most 2,000 characters.'
  else if (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(compact)) errors.config = 'Escape control or formatting characters in JSON strings.'
  return compact
}

export function addProvider(types: ProviderType[]): OperationDef {
  return {
    key: 'provider-add',
    title: 'Add provider',
    confirmLabel: 'Add provider',
    warning: credentialNotice,
    fields: [
      { name: 'name', label: 'Provider name', kind: 'text', required: true, maxLength: 64 },
      { name: 'type', label: 'Provider type', kind: 'select', required: true,
        options: types.map(({ type }) => ({ value: type, label: type === bitwarden ? 'Bitwarden Secrets Manager' : type === vault ? 'HashiCorp Vault'
          : type === lastPassRefresh ? 'LastPass' : type })) },
      { ...tokenField, visible: (values) => text(values, 'type') === onePassword },
      { ...vaultTokenField, visible: (values) => text(values, 'type') === vault },
      ...bitwardenFields.map((field) => ({ ...field, visible: (values: FormValues) => text(values, 'type') === bitwarden })),
      { ...lastPassUsernameField, visible: (values) => text(values, 'type') === lastPassRefresh },
      { ...lastPassRegionField, visible: (values) => text(values, 'type') === lastPassRefresh },
      { ...jsonField, visible: (values) => ![onePassword, bitwarden, lastPassRefresh, vault].includes(text(values, 'type')) },
      ...durationFields,
    ],
    initial: { type: types[0]?.type ?? '', config: '{}', lastPassRegion: 'us', ...bitwardenDefaults,
      ...durationValues(types[0]?.type === lastPassRefresh ? 3600 : 0) },
    prepare(values) {
      const errors: Record<string, string> = {}
      const name = text(values, 'name')
      const type = text(values, 'type')
      if (!name || name.length > 64) errors.name = 'Enter a provider name of 1 to 64 characters.'
      if (!types.some((item) => item.type === type)) errors.type = 'Choose a provider type.'
      const config = providerConfiguration(type, values, errors)
      const seconds = maxStale(values, errors)
      if (type === lastPassRefresh && seconds === '0') errors.hours = 'Set how long LastPass values may be used after a refresh.'
      if (Object.keys(errors).length) return { errors }

      return { operation: 'provider-add', parameters: { name, type, config, 'max-stale-seconds': seconds }, summary: `Add provider ${name}.`, done: `Added provider ${name}.` }
    },
    prepareForValidation,
    validate: ({ parameters }, signal) => api.post('/api/v1/providers/validate', { body: { type: String(parameters.type), config: String(parameters.config) }, signal }),
  }
}

export function changeProviderConfig(provider: Provider): OperationDef {
  return {
    key: 'provider-config',
    title: 'Change configuration',
    confirmLabel: 'Save configuration',
    warning: [onePassword, lastPassRefresh, vault].includes(provider.type) ? undefined : credentialNotice,
    about: [['Provider', provider.name]],
    fields: provider.type === bitwarden ? bitwardenFields
      : provider.type === onePassword ? [tokenField]
        : provider.type === vault ? [vaultTokenField]
          : provider.type === lastPassRefresh ? [lastPassUsernameField, lastPassRegionField] : [jsonField],
    initial: initialConfiguration(provider),
    prepare(values) {
      const errors: Record<string, string> = {}
      const config = providerConfiguration(provider.type, values, errors)
      if (Object.keys(errors).length) return { errors }

      return { operation: 'provider-config', parameters: { id: provider.id, revision: String(provider.revision), config }, summary: `Change configuration for ${provider.name}.`, done: 'Configuration saved.' }
    },
    prepareForValidation: provider.type === onePassword ? sealOnePassword : provider.type === vault ? sealVault : undefined,
    validate: ({ parameters }, signal) => api.post('/api/v1/providers/validate', { body: { type: provider.type, config: String(parameters.config) }, signal }),
  }
}

export function changeMaxStale(provider: Provider): OperationDef {
  return {
    key: 'provider-max-stale',
    title: 'Change maximum staleness',
    confirmLabel: 'Save cache policy',
    about: [['Provider', provider.name]],
    fields: provider.type === lastPassRefresh
      ? durationFields.map(field => field.name === 'hours' ? { ...field, hint: 'Cached values can be used for this long after a manual refresh.' } : field)
      : durationFields,
    initial: durationValues(provider.maxStaleSeconds),
    prepare(values) {
      const errors: Record<string, string> = {}
      const seconds = maxStale(values, errors)
      if (provider.type === lastPassRefresh && seconds === '0') errors.hours = 'Set how long LastPass values may be used after a refresh.'
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

export function addMount(provider: Provider): OperationDef {
  const interactive = provider.type === lastPassRefresh
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
      { name: 'kind', label: 'Mount kind', kind: 'select', options: [{ value: 'tree', label: 'Tree' }, { value: 'single', label: 'Single secret' }] },
      { name: 'path', label: 'Logical path', kind: 'text', required: true, maxLength: 200 },
      { name: 'base', label: 'Provider path', kind: 'text', maxLength: 300, hint: provider.type === bitwarden
        ? 'Use a lowercase project UUID for a tree mount. For a single secret, append /S_ followed by the lowercase secret UUID without hyphens.'
        : provider.type === vault
          ? 'Use a document path for its fields, end a folder path with /, or leave it blank for the KV mount root. For a single secret, use document/field.'
          : 'For a tree mount, leave blank to use the provider root.' },
    ],
    initial: interactive ? { kind: 'single', itemField: 'F_70617373776F7264' } : { kind: 'tree' },
    prepare(values) {
      const errors: Record<string, string> = {}
      const kind = interactive ? 'single' : text(values, 'kind')
      const path = text(values, 'path')
      const id = text(values, 'itemId')
      const field = text(values, 'itemField')
      const base = interactive ? `${id}/${field}` : text(values, 'base')
      if (interactive && !/^[1-9][0-9]{0,31}$/.test(id)) errors.itemId = 'Enter the numeric LastPass item ID.'
      if (interactive && !Object.hasOwn(lastPassFields, field)) errors.itemField = 'Choose a LastPass field.'
      if (kind !== 'tree' && kind !== 'single') errors.kind = 'Choose a mount kind.'
      if (!path || path.length > 200) errors.path = 'Enter a logical path of 1 to 200 characters.'
      if (kind === 'single' && !base) errors.base = 'Enter the provider path to the secret.'
      if (Object.keys(errors).length) return { errors }

      return { operation: 'mount-add', parameters: { instance: provider.id, kind, path, base }, summary: `Mount ${provider.name} at ${path}.`, done: `Added mount ${path}.` }
    },
    validate: ({ parameters }, signal) => api.post('/api/v1/providers/validate', { body: { instance: provider.id, mountBase: String(parameters.base), mountKind: parameters.kind === 'single' ? 'single' : 'tree' }, signal }),
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
