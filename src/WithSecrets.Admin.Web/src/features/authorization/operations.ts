import { api } from '../../api/client'
import type { Grant, Machine, MutationResponse, OperationName, ParameterValue, Passkey } from '../../api/types'

/**
 * Every administrative change the page can ask for, as data: what the person fills in, the exact operation and parameters the passkey will
 * authorize (identical in the authorization request and in the mutation that spends it), and the call that performs it.
 * The server enforces all of it; nothing here is a security control.
 */

export type FieldDef = {
  name: string
  label: string
  kind: 'text' | 'number' | 'checkbox'
  hint?: string
  required?: boolean
  min?: number
  max?: number
  maxLength?: number
}

export type FormValues = Record<string, string | boolean>

export type Prepared = {
  operation: OperationName
  parameters: Record<string, ParameterValue>
  /** One sentence naming what will happen, shown before the passkey page is asked for. */
  summary: string
  perform: (authorization: string) => Promise<MutationResponse>
}

export type OperationDef = {
  key: string
  title: string
  intro?: string
  /** Name/value pairs about the thing being changed, shown in every step. */
  about?: ReadonlyArray<readonly [string, string]>
  /** A warning shown before the person continues. */
  warning?: string
  danger?: boolean
  fields?: FieldDef[]
  initial?: FormValues
  /** Validates the form and gives the exact operation, or the errors by field name. */
  prepare: (values: FormValues) => { errors: Record<string, string> } | Prepared
}


function text(values: FormValues, name: string): string {
  const value = values[name]

  return typeof value === 'string' ? value.trim() : ''
}

function integer(values: FormValues, field: FieldDef, errors: Record<string, string>): number | null {
  const raw = text(values, field.name)
  if (!/^[0-9]+$/.test(raw)) {
    errors[field.name] = `Enter a whole number${field.min !== undefined && field.max !== undefined ? ` from ${field.min} to ${field.max}` : ''}.`

    return null
  }
  const number = Number(raw)
  if ((field.min !== undefined && number < field.min) || (field.max !== undefined && number > field.max)) {
    errors[field.name] = `Enter a whole number from ${field.min} to ${field.max}.`

    return null
  }

  return number
}

function simple(key: string, title: string, operation: OperationName, summary: string, perform: (authorization: string) => Promise<MutationResponse>, extra: Partial<OperationDef> = {}): OperationDef {
  return { key, title, ...extra, prepare: () => ({ operation, parameters: {}, summary, perform }) }
}

// ---- the authority ----

export const unlock = (): OperationDef =>
  simple('unlock', 'Unlock the authority', 'unlock', 'Unlock the authority so that secret requests can be served again.', (authorization) => api.post('/api/v1/unlock', { body: { authorization } }), {
    intro: 'Unlocking needs your passkey. It does not need a signed-in session.',
  })

export const lock = (): OperationDef =>
  simple('lock', 'Lock the authority', 'lock', 'Lock the authority now: secret requests stop, held keys are discarded, and every session and authorization ends.', (authorization) => api.post('/api/v1/lock', { body: { authorization } }), {
    danger: true,
    warning: 'Every signed-in session ends, including this one. You will need to unlock and sign in again.',
  })

export const rotateAuthorityKey = (): OperationDef =>
  simple('rotate-key', 'Rotate the authority signing key', 'authority-key-rotate', 'Rotate the authority signing key (a transition the current key signs).', (authorization) => api.post('/api/v1/authority-key/rotate', { body: { authorization } }), {
    intro: 'Hosts follow the transition the current key signs.',
  })

export const recoverAuthorityKey = (): OperationDef =>
  simple('recover-key', 'Recover the authority signing key', 'authority-key-recover', 'Recover the authority signing key without a transition.', (authorization) => api.post('/api/v1/authority-key/recover', { body: { authorization } }), {
    danger: true,
    warning: 'There is no transition: every other host has to enroll again.',
  })

// ---- settings ----

export const setUnlockPolicy = (policy: 'manual' | 'unattended'): OperationDef =>
  simple(
    'policy-' + policy,
    policy === 'manual' ? 'Require a manual unlock' : 'Allow unattended unlock',
    policy === 'manual' ? 'policy-manual' : 'policy-unattended',
    policy === 'manual' ? 'Set the unlock mode to manual: the authority stays locked after a start until you unlock it.' : 'Set the unlock mode to unattended: the authority unlocks itself at start without a passkey tap.',
    (authorization) => api.put('/api/v1/settings/unlock-policy', { body: { authorization, policy } }),
    policy === 'unattended' ? { danger: true, warning: 'This is the weaker mode: anyone who can start this service as you gets an unlocked authority.' } : {},
  )

const retentionField: FieldDef = { name: 'days', label: 'Days to keep audit events', kind: 'number', hint: '0 keeps everything.', required: true, min: 0, max: 36500 }

export const setAuditRetention = (current: number, max: number): OperationDef => ({
  key: 'audit-retention',
  title: 'Change audit retention',
  fields: [{ ...retentionField, max }],
  initial: { days: String(current) },
  prepare: (values) => {
    const errors: Record<string, string> = {}
    const days = integer(values, { ...retentionField, max }, errors)
    if (days === null) return { errors }

    return {
      operation: 'set-audit-retention',
      parameters: { days },
      summary: days === 0 ? 'Keep audit events for ever.' : `Keep audit events for ${days} days.`,
      perform: (authorization) => api.put('/api/v1/settings/audit-retention', { body: { authorization, days } }),
    }
  },
})

export const setSessionTimeouts = (idle: number, absolute: number, maxIdle: number, maxAbsolute: number): OperationDef => {
  const idleField: FieldDef = { name: 'idle', label: 'Idle timeout (minutes)', kind: 'number', hint: 'A session ends after this long without use.', required: true, min: 1, max: maxIdle }
  const absoluteField: FieldDef = { name: 'absolute', label: 'Absolute timeout (minutes)', kind: 'number', hint: 'A session ends after this long however busy it is.', required: true, min: 1, max: maxAbsolute }

  return {
    key: 'session-timeouts',
    title: 'Change session timeouts',
    fields: [idleField, absoluteField],
    initial: { idle: String(idle), absolute: String(absolute) },
    prepare: (values) => {
      const errors: Record<string, string> = {}
      const idleMinutes = integer(values, idleField, errors)
      const absoluteMinutes = integer(values, absoluteField, errors)
      if (idleMinutes === null || absoluteMinutes === null) return { errors }

      return {
        operation: 'set-session-timeouts',
        parameters: { idle: idleMinutes, absolute: absoluteMinutes },
        summary: `End a session after ${idleMinutes} minutes without use, or ${absoluteMinutes} minutes at most.`,
        perform: (authorization) => api.put('/api/v1/settings/session-timeouts', { body: { authorization, idle: idleMinutes, absolute: absoluteMinutes } }),
      }
    },
  }
}

// ---- machines ----

const nameField = (label: string, required: boolean, hint?: string): FieldDef => ({ name: 'name', label, kind: 'text', required, maxLength: 40, ...(hint ? { hint } : {}) })

function machineFacts(machine: Machine): ReadonlyArray<readonly [string, string]> {
  return [
    ['Machine', machine.friendlyName ?? machine.hostName],
    ['Fingerprint', machine.display],
    ['Status', machine.status],
  ]
}

export function approveMachine(machine: Machine): OperationDef {
  // A pending machine is approved under a name (the service refuses an empty one); re-pinning the key of an already trusted machine needs none.
  const named = machine.status === 'pending'
  const field = nameField('Friendly name', named, named ? 'Shown instead of the host name.' : 'Shown instead of the host name. Optional.')

  return {
    key: 'machine-approve',
    title: machine.status === 'pending' ? 'Approve this machine' : 'Re-pin the authority key for this machine',
    about: machineFacts(machine),
    fields: [field],
    initial: { name: machine.friendlyName ?? '' },
    prepare: (values) => {
      const name = text(values, 'name')
      if (named && !name) return { errors: { name: 'Enter a friendly name.' } }
      if (name.length > 40) return { errors: { name: 'Use at most 40 characters.' } }
      const parameters: Record<string, ParameterValue> = { fingerprint: machine.fingerprint, ...(name ? { name } : {}) }

      return {
        operation: 'machine-approve',
        parameters,
        summary: `Approve machine ${machine.display}${name ? ` as "${name}"` : ''}.`,
        perform: (authorization) => api.post('/api/v1/machines/{fingerprint}/approve', { path: { fingerprint: machine.fingerprint }, body: { authorization, ...(name ? { name } : {}) } }),
      }
    },
  }
}

function machineSimple(machine: Machine, key: string, title: string, operation: OperationName, summary: string, path: '/api/v1/machines/{fingerprint}/disable' | '/api/v1/machines/{fingerprint}/enable' | '/api/v1/machines/{fingerprint}/untrust' | '/api/v1/machines/{fingerprint}/approve-host-change', extra: Partial<OperationDef> = {}): OperationDef {
  return {
    key,
    title,
    about: machineFacts(machine),
    ...extra,
    prepare: () => ({
      operation,
      parameters: { fingerprint: machine.fingerprint },
      summary,
      perform: (authorization) => api.post(path, { path: { fingerprint: machine.fingerprint }, body: { authorization } }),
    }),
  }
}

export const disableMachine = (machine: Machine) =>
  machineSimple(machine, 'machine-disable', 'Disable this machine', 'machine-disable', `Disable machine ${machine.display}: it is denied until enabled, and its grants end.`, '/api/v1/machines/{fingerprint}/disable', { danger: true })

export const enableMachine = (machine: Machine) => machineSimple(machine, 'machine-enable', 'Enable this machine', 'machine-enable', `Enable machine ${machine.display}; it starts clean.`, '/api/v1/machines/{fingerprint}/enable')

export const untrustMachine = (machine: Machine) =>
  machineSimple(machine, 'machine-untrust', 'Withdraw trust from this machine', 'machine-untrust', `Withdraw trust from machine ${machine.display}.`, '/api/v1/machines/{fingerprint}/untrust', { danger: true })

export const approveHostChange = (machine: Machine) =>
  machineSimple(machine, 'machine-host-change', 'Accept the new host name', 'machine-host-change', `Accept the host name "${machine.pendingHostName ?? ''}" that machine ${machine.display} reported.`, '/api/v1/machines/{fingerprint}/approve-host-change', {
    intro: `The machine now reports the host name "${machine.pendingHostName ?? ''}" instead of "${machine.hostName}". Accept it only if you expected the change.`,
  })

export function renameMachine(machine: Machine): OperationDef {
  const field = nameField('New name', true)

  return {
    key: 'machine-rename',
    title: 'Rename this machine',
    about: machineFacts(machine),
    fields: [field],
    initial: { name: machine.friendlyName ?? '' },
    prepare: (values) => {
      const name = text(values, 'name')
      if (!name) return { errors: { name: 'Enter a name.' } }
      if (name.length > 40) return { errors: { name: 'Use at most 40 characters.' } }

      return {
        operation: 'machine-rename',
        parameters: { fingerprint: machine.fingerprint, name },
        summary: `Rename machine ${machine.display} to "${name}" (display only).`,
        perform: (authorization) => api.post('/api/v1/machines/{fingerprint}/rename', { path: { fingerprint: machine.fingerprint }, body: { authorization, name } }),
      }
    },
  }
}

const normalizeFingerprint = (value: string) => value.replace(/[^0-9a-fA-F]/g, '').toLowerCase()

export function trustMachine(machine: Machine): OperationDef {
  const field: FieldDef = { name: 'confirm', label: 'Type the full fingerprint to confirm', kind: 'text', required: true, hint: `Type exactly: ${machine.display}`, maxLength: 80 }

  return {
    key: 'machine-trust',
    title: 'Trust this machine again',
    about: machineFacts(machine),
    danger: true,
    fields: [field],
    initial: { confirm: '' },
    prepare: (values) => {
      const confirm = text(values, 'confirm')
      if (normalizeFingerprint(confirm) !== normalizeFingerprint(machine.fingerprint)) return { errors: { confirm: 'This is not the machine\'s full fingerprint.' } }

      return {
        operation: 'machine-trust',
        parameters: { fingerprint: machine.fingerprint, confirm },
        summary: `Trust machine ${machine.display} again.`,
        perform: (authorization) => api.post('/api/v1/machines/{fingerprint}/trust', { path: { fingerprint: machine.fingerprint }, body: { authorization, confirm } }),
      }
    },
  }
}

// ---- grants ----

function grantFacts(grant: Grant): ReadonlyArray<readonly [string, string]> {
  return [
    ['Grant', grant.id],
    ['Machine', grant.machineName ?? grant.fingerprint],
    ['Secrets (names only)', grant.secretNames],
    ['Program', grant.program],
    ['Ends', grant.ends],
  ]
}

export const revokeGrant = (grant: Grant): OperationDef => ({
  key: 'grant-revoke',
  title: 'Revoke this grant',
  about: grantFacts(grant),
  danger: true,
  prepare: () => ({
    operation: 'grant-revoke',
    parameters: { id: grant.id },
    summary: `Revoke grant ${grant.id}: it ends now and its machine is told.`,
    perform: (authorization) => api.post('/api/v1/grants/{id}/revoke', { path: { id: grant.id }, body: { authorization } }),
  }),
})

export function changeGrantEnd(grant: Grant, verb: 'extend' | 'renew'): OperationDef {
  const minutes: FieldDef = { name: 'minutes', label: verb === 'extend' ? 'Minutes to add to the present end' : 'Minutes from now', kind: 'number', min: 1, max: 1440, hint: 'From 1 to 1440.' }
  const indefinite: FieldDef = { name: 'indefinite', label: 'No end (indefinite)', kind: 'checkbox', hint: 'The grant then never ends by itself. Revoke it to end it.' }

  return {
    key: 'grant-' + verb,
    title: verb === 'extend' ? 'Extend this grant' : 'Renew this grant',
    about: grantFacts(grant),
    fields: [minutes, indefinite],
    initial: { minutes: '60', indefinite: false },
    prepare: (values) => {
      const errors: Record<string, string> = {}
      const never = values.indefinite === true
      let count: number | null = null
      if (!never) count = integer(values, { ...minutes, required: true }, errors)
      if (!never && count === null) return { errors }
      const parameters: Record<string, ParameterValue> = never ? { id: grant.id, indefinite: true } : { id: grant.id, minutes: count as number }
      const body = never ? { indefinite: true } : { minutes: count as number }
      const summary = never
        ? `${verb === 'extend' ? 'Extend' : 'Renew'} grant ${grant.id} so that it has no end.`
        : verb === 'extend'
          ? `Extend grant ${grant.id} by ${count} minutes from its present end.`
          : `Renew grant ${grant.id} for ${count} minutes from now.`

      return {
        operation: verb === 'extend' ? 'grant-extend' : 'grant-renew',
        parameters,
        summary,
        perform: (authorization) => api.post(verb === 'extend' ? '/api/v1/grants/{id}/extend' : '/api/v1/grants/{id}/renew', { path: { id: grant.id }, body: { authorization, ...body } }),
      }
    },
  }
}

// ---- passkeys ----

export const addPasskey = (): OperationDef =>
  simple('passkey-add', 'Add a passkey', 'passkey-enroll', 'Add a passkey: the enrollment pages follow, each with its own passkey tap.', (authorization) => api.post('/api/v1/passkeys', { body: { authorization } }), {
    intro: 'After this authorization the enrollment pages open one after another. Each asks for its own passkey tap.',
  })

export const removePasskey = (passkey: Passkey): OperationDef => ({
  key: 'passkey-remove',
  title: 'Remove this passkey',
  about: [
    ['Passkey', passkey.name],
    ['Kind', passkey.detail],
  ],
  danger: true,
  warning: 'The last admin passkey cannot be removed.',
  prepare: () => ({
    operation: 'passkey-unenroll',
    parameters: { name: passkey.name },
    summary: `Remove the passkey "${passkey.name}".`,
    perform: (authorization) => api.post('/api/v1/passkeys/{name}/remove', { path: { name: passkey.name }, body: { authorization } }),
  }),
})
