import { api } from '../../api/client'
import type { Mount, Provider, ProviderType } from '../../api/types'
import type { FieldDef, FormValues, OperationDef } from '../authorization/operations'

const credentialNotice = 'Do not put passwords or tokens in the configuration. Credential entry is not available yet.'
const maxConfig = 2_000
const durationFields: FieldDef[] = [
  { name: 'hours', label: 'Hours', kind: 'number', hint: 'The maximum is 24 hours. Use zero to disable stale delivery.' },
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

// Adapter-specific editors can extend this registry while retaining the same signed JSON parameter.
const configurationFields = new Map<string, FieldDef>()
function formFor(type: string): FieldDef {
  return configurationFields.get(type) ?? { name: 'config', label: 'Configuration JSON', kind: 'textarea', required: true, maxLength: maxConfig }
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
      { name: 'type', label: 'Provider type', kind: 'select', required: true, options: types.map(({ type }) => ({ value: type, label: type })) },
      formFor(types[0]?.type ?? ''),
      ...durationFields,
    ],
    initial: { type: types[0]?.type ?? '', config: '{}', ...durationValues(3600) },
    prepare(values) {
      const errors: Record<string, string> = {}
      const name = text(values, 'name')
      const type = text(values, 'type')
      if (!name || name.length > 64) errors.name = 'Enter a provider name of 1 to 64 characters.'
      if (!types.some((item) => item.type === type)) errors.type = 'Choose a provider type.'
      const config = configuration(values, errors)
      const seconds = maxStale(values, errors)
      if (Object.keys(errors).length) return { errors }

      return { operation: 'provider-add', parameters: { name, type, config, 'max-stale-seconds': seconds }, summary: `Add provider ${name}.`, done: `Added provider ${name}.` }
    },
    validate: ({ parameters }, signal) => api.post('/api/v1/providers/validate', { body: { type: String(parameters.type), config: String(parameters.config) }, signal }),
  }
}

export function changeProviderConfig(provider: Provider): OperationDef {
  return {
    key: 'provider-config',
    title: 'Change configuration',
    confirmLabel: 'Save configuration',
    warning: credentialNotice,
    about: [['Provider', provider.name]],
    fields: [formFor(provider.type)],
    initial: { config: provider.configuration },
    prepare(values) {
      const errors: Record<string, string> = {}
      const config = configuration(values, errors)
      if (Object.keys(errors).length) return { errors }

      return { operation: 'provider-config', parameters: { id: provider.id, revision: String(provider.revision), config }, summary: `Change configuration for ${provider.name}.`, done: 'Configuration saved.' }
    },
    validate: ({ parameters }, signal) => api.post('/api/v1/providers/validate', { body: { type: provider.type, config: String(parameters.config) }, signal }),
  }
}

export function changeMaxStale(provider: Provider): OperationDef {
  return {
    key: 'provider-max-stale',
    title: 'Change maximum staleness',
    confirmLabel: 'Save cache policy',
    about: [['Provider', provider.name]],
    fields: durationFields,
    initial: durationValues(provider.maxStaleSeconds),
    prepare(values) {
      const errors: Record<string, string> = {}
      const seconds = maxStale(values, errors)
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
  return {
    key: 'mount-add',
    title: 'Add mount',
    confirmLabel: 'Add mount',
    about: [['Provider', provider.name]],
    fields: [
      { name: 'kind', label: 'Mount kind', kind: 'select', options: [{ value: 'tree', label: 'Tree' }, { value: 'single', label: 'Single secret' }] },
      { name: 'path', label: 'Logical path', kind: 'text', required: true, maxLength: 200 },
      { name: 'base', label: 'Provider path', kind: 'text', maxLength: 300, hint: 'For a tree mount, leave blank to use the provider root.' },
    ],
    initial: { kind: 'tree' },
    prepare(values) {
      const errors: Record<string, string> = {}
      const kind = text(values, 'kind')
      const path = text(values, 'path')
      const base = text(values, 'base')
      if (kind !== 'tree' && kind !== 'single') errors.kind = 'Choose a mount kind.'
      if (!path || path.length > 200) errors.path = 'Enter a logical path of 1 to 200 characters.'
      if (kind === 'single' && !base) errors.base = 'Enter the provider path to the secret.'
      if (Object.keys(errors).length) return { errors }

      return { operation: 'mount-add', parameters: { instance: provider.id, kind, path, base }, summary: `Mount ${provider.name} at ${path}.`, done: `Added mount ${path}.` }
    },
    validate: ({ parameters }, signal) => api.post('/api/v1/providers/validate', { body: { instance: provider.id, mountBase: String(parameters.base) }, signal }),
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
