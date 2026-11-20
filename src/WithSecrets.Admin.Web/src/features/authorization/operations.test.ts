import { describe, expect, it } from 'vitest'
import { grant, machine } from '../../test/fakeApi'
import { addPasskey, approveMachine, rotateStoreKey, changeGrantEnd, recoverAuthorityKey, removePasskey, renameMachine, revokeGrant, rotateAuthorityKey, setAuditRetention, setSessionTimeouts, setUnlockPolicy, trustMachine, unlock, type OperationDef, type Prepared } from './operations'

function prepared(def: OperationDef, values: Record<string, string | boolean> = {}): Prepared {
  const result = def.prepare(values)
  if ('errors' in result) throw new Error('errors: ' + JSON.stringify(result.errors))

  return result
}

describe('operations: what is authorized is exactly what is performed', () => {
  it('machine approve: the authorized parameters are the fingerprint and the name; a pending machine starts with its host name', () => {
    const m = machine()
    const p = prepared(approveMachine(m), { name: 'ci box' })
    expect(p.operation).toBe('machine-approve')
    expect(p.parameters).toEqual({ fingerprint: m.fingerprint, name: 'ci box' })
    expect(approveMachine(m).initial).toEqual({ name: 'build-host' })
    expect(p.summary).toContain('ci box')
  })

  it('needs a name to approve a pending machine, and leaves an empty optional name out when re-pinning a trusted one', () => {
    expect(approveMachine(machine()).prepare({ name: '  ' })).toEqual({ errors: { name: 'Enter a friendly name.' } })
    expect(prepared(approveMachine(machine({ status: 'trusted', thisMachine: true })), { name: '  ' }).parameters).toEqual({ fingerprint: machine().fingerprint })
  })

  it('refuses an invalid form before anything is asked of the service', () => {
    expect(renameMachine(machine()).prepare({ name: '' })).toEqual({ errors: { name: 'Enter a name.' } })
    expect(renameMachine(machine()).prepare({ name: 'x'.repeat(41) })).toHaveProperty('errors.name')
    expect(setAuditRetention(90, 36500).prepare({ days: '-1' })).toHaveProperty('errors.days')
    expect(setAuditRetention(90, 36500).prepare({ days: '36501' })).toHaveProperty('errors.days')
    expect(setSessionTimeouts(15, 480, 120, 1440).prepare({ idle: '0', absolute: '10' })).toHaveProperty('errors.idle')
  })

  it('trust needs the full fingerprint typed again', () => {
    const m = machine({ status: 'untrusted' })
    expect(trustMachine(m).prepare({ confirm: 'ab12 cd34' })).toHaveProperty('errors.confirm')
    const ok = prepared(trustMachine(m), { confirm: 'AB12 CD34 EF56 AB12 CD34 EF56 AB12 CD34 EF56 AB12 CD34 EF56 AB12 CD34 EF56 AB12' })
    expect(ok.operation).toBe('machine-trust')
    expect(ok.parameters.fingerprint).toBe(m.fingerprint)
  })

  it('grant extend: minutes, or no end, never both; revoke names only the grant', () => {
    const g = grant()
    expect(prepared(changeGrantEnd(g, 'extend'), { minutes: '30', indefinite: false }).parameters).toEqual({ id: 'grant-0001', minutes: 30 })
    expect(prepared(changeGrantEnd(g, 'extend'), { minutes: '30', indefinite: true }).parameters).toEqual({ id: 'grant-0001', indefinite: true })
    expect(changeGrantEnd(g, 'renew').prepare({ minutes: '2000', indefinite: false })).toHaveProperty('errors.minutes')
    expect(prepared(revokeGrant(g)).parameters).toEqual({ id: 'grant-0001' })
    expect(prepared(revokeGrant(g)).operation).toBe('grant-revoke')
  })

  it('the unlock mode is the operation (policy-manual / policy-unattended), with no parameters', () => {
    const p = prepared(setUnlockPolicy('unattended'))
    expect(p.operation).toBe('policy-unattended')
    expect(p.parameters).toEqual({})
    expect(prepared(unlock()).operation).toBe('unlock')
  })

  it('passkey removal names the passkey', () => {
    const p = prepared(removePasskey({ name: 'old key', detail: 'x', created: '2026-01-01T00:00:00Z', admin: false }))
    expect(p.parameters).toEqual({ name: 'old key' })
  })

  it('settings reviews state the exact effect before the passkey tap', () => {
    expect(prepared(setAuditRetention(90, 36500), { days: '0' }).summary).toBe('Keep audit events for ever.')
    expect(prepared(setSessionTimeouts(15, 480, 120, 1440), { idle: '15', absolute: '480' }).summary).toBe('End a session after 15 minutes without use, or 480 minutes at most.')
    expect(prepared(setUnlockPolicy('unattended')).summary).toContain('unlocks itself at start')
    expect(setUnlockPolicy('unattended').warning).toBe('Weaker: anyone who can start this service as you gets an unlocked authority.')
  })

  it('rotation follows a transition while recovery has no transition and enrolls every other host again', () => {
    expect(rotateAuthorityKey().danger).toBeFalsy()
    expect(rotateAuthorityKey().confirmLabel).toBe('Rotate key')
    expect(rotateAuthorityKey().warning).toBeUndefined()
    expect(recoverAuthorityKey().danger).toBe(true)
    expect(recoverAuthorityKey().warning).toBe('Every other machine has to be paired again.')
  })

  it('rotating the store key authorizes the store-key-rotate operation with no parameters and warns about the recovery code', () => {
    const p = prepared(rotateStoreKey())
    expect(p.operation).toBe('store-key-rotate')
    expect(p.parameters).toEqual({})
    expect(rotateStoreKey().danger).toBe(true)
    expect(rotateStoreKey().warning).toContain('recovery code')
  })

  it('adding a passkey starts its own delegated enrollment sequence', () => {
    const p = prepared(addPasskey())
    expect(p.operation).toBe('passkey-enroll')
    expect(p.summary).toBe('Add a passkey: the enrollment pages follow, each with its own passkey tap.')
    expect(addPasskey().intro).toBe('Tap your passkey on each page that opens.')
  })
})
