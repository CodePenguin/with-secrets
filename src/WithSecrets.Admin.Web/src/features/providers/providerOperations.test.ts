import { describe, expect, it } from 'vitest'
import { mount, provider } from '../../test/fakeApi'
import { addMount, addProvider, changeMaxStale, changeProviderConfig, removeMount, removeProvider } from './providerOperations'

describe('provider operations', () => {
  it('prepares the exact operations and canonical parameters', () => {
    const config = '{"serverUrl":"https://vault.bitwarden.com","encryptedConfiguration":"sealed-fixture"}'
    const instance = provider({ type: 'bitwarden', configuration: config })
    const mounted = mount()
    const create = addProvider([{ type: 'bitwarden', adapterVersion: '1' }])
    expect(create.prepare({ ...create.initial, name: ' Build vault ', type: 'bitwarden', bitwardenToken: 'mock-token', hours: '1', minutes: '15' }))
      .toMatchObject({ operation: 'provider-add', parameters: { name: instance.name, type: 'bitwarden', config: '{}', 'max-stale-seconds': '4500' } })
    const edit = changeProviderConfig(instance)
    expect(edit.prepare({ ...edit.initial, minutes: '15' })).toMatchObject({ operation: 'provider-config', parameters: { id: instance.id, revision: '2', config: instance.configuration, 'max-stale-seconds': '4500' } })
    const duration = changeMaxStale(instance)
    expect(duration.prepare(duration.initial!)).toMatchObject({ operation: 'provider-max-stale', parameters: { id: instance.id, revision: '2', 'max-stale-seconds': '3601' } })
    expect(duration.prepare({ hours: '25' })).toHaveProperty('errors.hours')
    expect(duration.prepare({ hours: '24', minutes: '1' })).toHaveProperty('errors.hours')
    expect(removeProvider(instance).prepare({})).toMatchObject({ operation: 'provider-remove', parameters: { id: instance.id, revision: '2' } })
    expect(addMount(instance).prepare({ kind: 'tree', path: 'team', base: '' })).toMatchObject({ operation: 'mount-add', parameters: { instance: instance.id, kind: 'tree', path: 'team', base: '' } })
    expect(removeMount(mounted).prepare({})).toMatchObject({ operation: 'mount-remove', parameters: { id: mounted.id } })
  })
})
