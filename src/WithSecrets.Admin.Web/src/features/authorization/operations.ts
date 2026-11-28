import type { Grant, Invitation, Machine, OperationName, ParameterValue, Passkey, ProviderValidation } from '../../api/types'
import type { components } from '../../api/schema'

/**
 * Every administrative change the page can ask for, as data: what the person fills in, the exact operation and parameters the passkey will
 * authorize (what the authorization request carries; the service makes the change when the tap is verified, so this page makes no second call). The server enforces
 * all of it; nothing here is a security control.
 */

export type SelectOption = { value: string; label: string }

export type FieldDef = {
  name: string
  label: string
  kind: 'text' | 'password' | 'number' | 'checkbox' | 'select' | 'textarea'
  options?: ReadonlyArray<SelectOption>
  loadOptions?: (values: FormValues) => {
    key: readonly unknown[]
    load: (signal: AbortSignal) => Promise<SelectOption[]>
  }
  clearOnChange?: readonly string[]
  suggestions?: readonly string[]
  hint?: string
  required?: boolean
  min?: number
  max?: number
  maxLength?: number
  visible?: (values: FormValues) => boolean
}

export type FormValues = Record<string, string | boolean>

export type Prepared = {
  operation: OperationName
  parameters: Record<string, ParameterValue>
  /** One sentence naming what will happen, shown before the passkey page is asked for. */
  summary: string
  /** The same, said as done: shown once the change is made. */
  done: string
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
  fields?: FieldDef[] | ((values: FormValues) => FieldDef[])
  fieldGroup?: { label: string; hint: string; fields: FieldDef[]; visible?: (values: FormValues) => boolean }
  initial?: FormValues
  /** Ask for the passkey challenge as soon as the dialog opens, with the initial values (the person may still change them). */
  autoPrepare?: boolean
  /** A preceding duration-menu selection already supplied the confirmation gesture for the passkey prompt. */
  promptOnOpen?: boolean
  /** The name of the final button: what the tap does, in two or three words. */
  confirmLabel?: string
  applyFromSession?: boolean
  /** Discard any state held for this specific operation when its dialog closes. */
  onClose?: () => void
  /** Validates the form and gives the exact operation, or the errors by field name. */
  prepare: (values: FormValues) => { errors: Record<string, string> } | Prepared
  prepareForValidation?: (prepared: Prepared, values: FormValues, signal: AbortSignal) => Promise<{ prepared: Prepared; draft: FormValues }>
  validate?: (prepared: Prepared, signal: AbortSignal) => Promise<ProviderValidation>
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

function simple(key: string, title: string, operation: OperationName, summary: string, done: string, extra: Partial<OperationDef> = {}): OperationDef {
  return { key, title, ...extra, prepare: () => ({ operation, parameters: {}, summary, done }) }
}

// ---- the authority ----

export const unlock = (signIn = false): OperationDef => ({
  key: 'unlock',
  title: signIn ? 'Unlock and sign in' : 'Unlock the authority',
  confirmLabel: signIn ? 'Unlock and sign in' : 'Unlock',
  prepare: () => ({ operation: 'unlock', parameters: { ...(signIn ? { 'sign-in': true } : {}) },
    summary: signIn ? 'Unlock the authority and open Admin in this browser.' : 'Unlock the authority so that secret requests can be served again.',
    done: signIn ? 'The authority is unlocked and you are signed in.' : 'The authority is unlocked.' }),
})

export const lock = (applyFromSession = false): OperationDef =>
  simple('lock', 'Lock the authority', 'lock', 'Lock the authority now. Secret requests stop and every session ends.', 'The authority is locked.', {
    danger: true,
    confirmLabel: 'Lock',
    warning: 'This ends every session, including this one.',
    applyFromSession,
  })

export const lockEditing = (): OperationDef =>
  simple('session-lock-editing', 'Lock editing', 'session-lock-editing', 'Require a passkey before making more changes in this session.', 'Editing is locked.', {
    applyFromSession: true, confirmLabel: 'Lock editing',
  })

export const resumeEditing = (): OperationDef =>
  simple('session-resume-editing', 'Resume editing', 'session-resume-editing', 'Use an admin passkey to resume editing.', 'Editing is unlocked.', {
    confirmLabel: 'Resume editing',
  })

export const addAuthenticator = (): OperationDef => ({
  key: 'authenticator-add',
  title: 'Add authenticator app',
  fields: [{ name: 'name', label: 'Name', kind: 'text', maxLength: 40, required: true }],
  confirmLabel: 'Add authenticator app',
  prepare: (values) => {
    const name = text(values, 'name')
    if (!name) return { errors: { name: 'Enter a name for this authenticator app.' } }
    return { operation: 'authenticator-add', parameters: { name }, summary: `Add ${name} to resume existing admin sessions.`, done: `${name} was added.` }
  },
})

export const removeAuthenticator = (id: string, name: string): OperationDef => ({
  key: 'authenticator-remove',
  title: `Remove ${name}`,
  danger: true,
  confirmLabel: 'Remove authenticator app',
  prepare: () => ({ operation: 'authenticator-remove', parameters: { id }, summary: `Remove ${name} from access credentials.`, done: `${name} was removed.` }),
})

export const rotateAuthorityKey = (): OperationDef =>
  simple('rotate-key', 'Rotate the authority signing key', 'authority-key-rotate', 'Rotate the authority signing key (a transition the current key signs).', 'The authority signing key was rotated.', {
    confirmLabel: 'Rotate key',
  })

export const recoverAuthorityKey = (): OperationDef =>
  simple('recover-key', 'Recover the authority signing key', 'authority-key-recover', 'Recover the authority signing key without a transition.', 'The authority signing key was recovered.', {
    danger: true,
    confirmLabel: 'Recover key',
    warning: 'Every other machine has to be paired again.',
  })

// ---- settings ----

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
      done: days === 0 ? 'Audit events are kept for ever.' : `Audit events are kept for ${days} days.`,
    }
  },
})

export const setSessionTimeouts = (idle: number, absolute: number, maxIdle: number, maxAbsolute: number): OperationDef => {
  const idleField: FieldDef = { name: 'idle', label: 'Lock editing after inactivity (minutes)', kind: 'number', hint: 'Enter 0 for Never.', required: true, min: 0, max: maxIdle }
  const absoluteField: FieldDef = { name: 'absolute', label: 'Sign out after (minutes)', kind: 'number', hint: 'A session ends after this long, however busy it is.', required: true, min: 1, max: maxAbsolute }

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
        summary: `Editing ${idleMinutes === 0 ? 'stays unlocked until the session ends' : `locks after ${idleMinutes} idle minutes`}. The session ends after ${absoluteMinutes} minutes.`,
        done: 'Session timeouts updated.',
      }
    },
  }
}

// ---- machines ----

const nameField = (label: string, required: boolean, hint?: string): FieldDef => ({ name: 'name', label, kind: 'text', required, maxLength: 40, ...(hint ? { hint } : {}) })

// The fingerprint is in the sentence the passkey signs (and under Details), so it is not listed here again.
function machineFacts(machine: Machine): ReadonlyArray<readonly [string, string]> {
  return [
    ['Machine', machine.friendlyName ?? machine.hostName],
    ['Status', machine.status],
  ]
}

export function approveMachine(machine: Machine): OperationDef {
  // A pending machine is approved under a name (the service refuses an empty one); re-pinning the key of an already trusted machine needs none.
  const named = machine.status === 'pending'
  const field = nameField('Friendly name', named, named ? 'Shown instead of the host name.' : 'Shown instead of the host name. Optional.')

  return {
    key: 'machine-approve',
    title: machine.status === 'pending' ? 'Approve this machine' : 'Accept the new authority key on this machine',
    about: machineFacts(machine),
    ...(named ? { intro: 'Approve only if the fingerprint and host name match what that machine shows.' } : {}),
    fields: [field],
    ...(named ? { autoPrepare: true } : {}),
    confirmLabel: named ? 'Approve machine' : 'Accept key',
    // A pending machine starts with its host name as the friendly name (the person may change it; the service still refuses an empty one).
    initial: { name: machine.friendlyName ?? (named ? machine.hostName.slice(0, 40) : '') },
    prepare: (values) => {
      const name = text(values, 'name')
      if (named && !name) return { errors: { name: 'Enter a friendly name.' } }
      if (name.length > 40) return { errors: { name: 'Use at most 40 characters.' } }
      const parameters: Record<string, ParameterValue> = { fingerprint: machine.fingerprint, ...(name ? { name } : {}) }

      return {
        operation: 'machine-approve',
        parameters,
        summary: `Approve machine ${machine.display}${name ? ` as "${name}"` : ''}.`,
        done: `Approved machine ${machine.display}${name ? ` as "${name}"` : ''}.`,
      }
    },
  }
}

function machineSimple(machine: Machine, key: string, title: string, operation: OperationName, summary: string, done: string, extra: Partial<OperationDef> = {}): OperationDef {
  return {
    key,
    title,
    about: machineFacts(machine),
    ...extra,
    prepare: () => ({
      operation,
      parameters: { fingerprint: machine.fingerprint },
      summary,
      done,
    }),
  }
}

export const disableMachine = (machine: Machine) =>
  machineSimple(machine, 'machine-disable', 'Disable this machine', 'machine-disable', `Disable machine ${machine.display}. It is denied until enabled and its grants end.`, `Disabled machine ${machine.display}.`, { danger: true, confirmLabel: 'Disable' })

export const enableMachine = (machine: Machine) => machineSimple(machine, 'machine-enable', 'Enable this machine', 'machine-enable', `Enable machine ${machine.display}; it starts clean.`, `Enabled machine ${machine.display}.`, { confirmLabel: 'Enable' })

export const untrustMachine = (machine: Machine) =>
  machineSimple(machine, 'machine-untrust', 'Withdraw trust from this machine', 'machine-untrust', `Withdraw trust from machine ${machine.display}.`, `Withdrew trust from machine ${machine.display}.`, { danger: true, confirmLabel: 'Withdraw trust' })

export const approveHostChange = (machine: Machine) =>
  machineSimple(machine, 'machine-host-change', 'Accept the new host name', 'machine-host-change', `Accept the host name "${machine.pendingHostName ?? ''}" that machine ${machine.display} reported.`, `Accepted the host name "${machine.pendingHostName ?? ''}" for machine ${machine.display}.`, {
    intro: `${machine.hostName} → ${machine.pendingHostName ?? ''}. Accept only if you expected the change.`,
    confirmLabel: 'Accept new name',
  })

export function renameMachine(machine: Machine): OperationDef {
  const field = nameField('New name', true)

  return {
    key: 'machine-rename',
    title: 'Rename this machine',
    about: machineFacts(machine),
    fields: [field],
    initial: { name: machine.friendlyName ?? '' },
    confirmLabel: 'Rename',
    prepare: (values) => {
      const name = text(values, 'name')
      if (!name) return { errors: { name: 'Enter a name.' } }
      if (name.length > 40) return { errors: { name: 'Use at most 40 characters.' } }

      return {
        operation: 'machine-rename',
        parameters: { fingerprint: machine.fingerprint, name },
        summary: `Rename machine ${machine.display} to "${name}" (display only).`,
        done: `Renamed machine ${machine.display} to "${name}".`,
      }
    },
  }
}

type MachineLogLevel = components['schemas']['MachineDiagnostics']['logLevel']

export const diagnosticLevels: Record<MachineLogLevel, string> = {
  error: 'Error',
  warning: 'Warning',
  information: 'Information',
  debug: 'Debug',
}

export function setMachineLogLevel(fingerprint: string, machineName: string, logLevel: MachineLogLevel): OperationDef {
  return {
    key: 'machine-log-level',
    title: 'Change log level',
    about: [['Machine', machineName]],
    fields: [
      { name: 'level', label: 'Log level', kind: 'select', required: true, options: Object.entries(diagnosticLevels).map(([value, label]) => ({ value, label })) },
    ],
    initial: { level: logLevel },
    confirmLabel: 'Save log level',
    prepare: (values) => {
      const level = text(values, 'level')
      if (!Object.hasOwn(diagnosticLevels, level)) return { errors: { level: 'Choose a log level.' } }

      return {
        operation: 'machine-log-level',
        parameters: { fingerprint, level },
        summary: `Set the log level for ${machineName} to ${diagnosticLevels[level as MachineLogLevel]}. This applies to local logs and diagnostics sent to Admin.`,
        done: `Updated the log level for ${machineName}.`,
      }
    },
  }
}

const normalizeFingerprint = (value: string) => value.replace(/[^0-9a-fA-F]/g, '').toLowerCase()

export function trustMachine(machine: Machine): OperationDef {
  const field: FieldDef = { name: 'confirm', label: 'Type the fingerprint to confirm', kind: 'text', required: true, hint: `Type exactly: ${machine.display}`, maxLength: 80 }

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
        done: `Trusted machine ${machine.display} again.`,
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

export const revokeGrant = (grant: Grant, applyFromSession = false): OperationDef => ({
  key: 'grant-revoke',
  applyFromSession,
  title: 'Revoke this grant',
  about: grantFacts(grant),
  danger: true,
  confirmLabel: 'Revoke grant',
  prepare: () => ({
    operation: 'grant-revoke',
    parameters: { id: grant.id },
    summary: `Revoke grant ${grant.id}: it ends now and its machine is told.`,
    done: `Revoked grant ${grant.id}.`,
  }),
})

export function changeGrantEnd(grant: Grant, verb: 'extend' | 'renew' | 'replace'): OperationDef {
  const minutes: FieldDef = { name: 'minutes', label: verb === 'extend' ? 'Minutes to add to the present end' : 'Minutes from now', kind: 'number', min: 1, max: 1440, hint: 'From 1 to 1440.' }
  const indefinite: FieldDef = { name: 'indefinite', label: 'No end', kind: 'checkbox', hint: 'The grant then never ends by itself. Revoke it to end it.' }

  return {
    key: 'grant-' + verb,
    title: verb === 'extend' ? 'Extend this grant' : verb === 'renew' ? 'Renew this grant' : 'Allow repeat runs',
    confirmLabel: verb === 'replace' ? 'Create grant' : undefined,
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
      const summary =
        verb === 'replace'
          ? never
            ? `Make a new grant with the same scope as used grant ${grant.id}, with no end.`
            : `Make a new grant with the same scope as used grant ${grant.id}, for ${count} minutes from now.`
          : never
            ? `${verb === 'extend' ? 'Extend' : 'Renew'} grant ${grant.id} so that it has no end.`
            : verb === 'extend'
              ? `Extend grant ${grant.id} by ${count} minutes from its present end.`
              : `Renew grant ${grant.id} for ${count} minutes from now.`

      return {
        operation: `grant-${verb}` as const,
        parameters,
        summary,
        done: summary.replace(/^Extend /, 'Extended ').replace(/^Renew /, 'Renewed ').replace(/^Make /, 'Made '),
      }
    },
  }
}

// ---- passkeys ----

export const addPasskey = (): OperationDef =>
  simple('passkey-add', 'Add a passkey', 'passkey-enroll', 'Add a passkey: the enrollment pages follow, each with its own passkey tap.', 'Adding a passkey started.', {
    intro: 'Tap your passkey on each page that opens.',
    confirmLabel: 'Add a passkey',
  })

export const rotateStoreKey = (): OperationDef =>
  simple('store-key-rotate', 'Rotate the secret store key', 'store-key-rotate', 'Replace the keys that protect your secrets. Two passkey pages follow.', 'Replacing the keys started.', {
    intro: 'Tap your passkey on each page. Only that passkey stays; add the others again afterwards.',
    confirmLabel: 'Rotate the keys',
    danger: true,
    warning: 'The old recovery code stops working.',
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
  confirmLabel: 'Remove passkey',
  prepare: () => ({
    operation: 'passkey-unenroll',
    parameters: { name: passkey.name },
    summary: `Remove the passkey "${passkey.name}".`,
    done: `Removed the passkey "${passkey.name}".`,
  }),
})

// ---- pairing ----

/** The service names the address and the lifetime in the sentence the passkey signs; this page only asks. */
export const createPairingInvitation = (): OperationDef =>
  simple('pairing-create', 'Create a pairing invitation', 'pairing-create', 'Create a one-time invitation for a new machine (valid 10 minutes).', 'Created a one-time invitation.', {
    intro: 'Copy the invitation to the new machine, then approve it here.',
    confirmLabel: 'Create invitation',
  })

export const revokePairingInvitation = (invitation: Invitation): OperationDef => ({
  key: 'pairing-revoke',
  applyFromSession: true,
  title: 'Revoke this invitation',
  about: [
    ['Invitation', invitation.id],
    ['Status', invitation.status],
  ],
  danger: true,
  confirmLabel: 'Revoke invitation',
  prepare: () => ({
    operation: 'pairing-revoke',
    parameters: { id: invitation.id },
    summary: `Revoke pairing invitation ${invitation.id}: it can no longer be used.`,
    done: `Revoked pairing invitation ${invitation.id}.`,
  }),
})
