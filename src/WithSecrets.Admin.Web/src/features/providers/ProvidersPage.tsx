import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { keys, useEntries, useMounts, useProviders, useProviderTypes, useSession, useStatus } from '../../api/queries'
import type { Mount, Provider } from '../../api/types'
import { Button } from '../../components/Button'
import { Badge, Empty, Facts, PageHeader } from '../../components/Card'
import { Loading, Notice, ProblemAlert, useAnnounce } from '../../components/Feedback'
import { Flash } from '../../components/Flash'
import list from '../../components/List.module.css'
import { Time } from '../../lib/format'
import { usePageTitle } from '../../lib/usePageTitle'
import { useStartOperation } from '../authorization/OperationProvider'
import type { OperationDef } from '../authorization/operations'
import { addMount, addProvider, changeMaxStale, changeProviderConfig, hasProviderForm, lastPassRefresh, providerTypeLabel, removeMount, removeProvider } from './providerOperations'
import { ProviderValueRefresh } from './ProviderValueRefresh'
import styles from './ProvidersPage.module.css'

const actions: Record<Exclude<Provider['actions'][number], 'refresh-values'>, (provider: Provider) => OperationDef> = {
  config: changeProviderConfig, 'max-stale': changeMaxStale, remove: removeProvider, 'add-mount': addMount,
}

function Duration({ seconds }: { seconds: number }) {
  if (!seconds) return <>Fetch fresh every time</>
  const parts = [Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60, seconds % 60]
    .map((value, index) => value ? `${value} ${['h', 'min', 's'][index]}` : '')
    .filter(Boolean)

  return <>{parts.join(' ')}</>
}

function ProviderFacts({ provider }: { provider: Provider }) {
  const status = provider.status
  const health = status?.health
  return (
    <Facts items={[
      ['Type', providerTypeLabel(provider.type)],
      ['Lifecycle', status ? <><span className={styles.state}>{status.lifecycle === 'shuttingdown' ? 'shutting down' : status.lifecycle}</span> · <Time value={status.lifecycleAt} />{status.lifecycleMessage ? <div>{status.lifecycleMessage}</div> : null}</> : 'Not running'],
      ['Health', status ? <><Badge tone={health === 'healthy' ? 'ok' : health === 'unavailable' || health === 'misconfigured' ? 'bad' : 'warn'}><span className={styles.state}>{health}</span></Badge> · <Time value={status.healthAt} />{status.healthMessage ? <div>{status.healthMessage}</div> : null}</> : 'Unknown'],
      ...(provider.type === lastPassRefresh ? [] : [['Cache freshness', <Duration seconds={provider.maxStaleSeconds} />] as const]),
      ['Mounts', provider.mounts],
    ]} />
  )
}

function ProviderActions({ provider, canChange }: { provider: Provider; canChange: boolean }) {
  const start = useStartOperation()
  if (!canChange) return null

  return (
    <div className={list.actions}>
      {provider.actions.map((action) => {
        if (action === 'refresh-values') return <ProviderValueRefresh key={action} provider={provider} />
        if (action === 'config' && !hasProviderForm(provider.type)) return null
        if (action === 'max-stale' && (provider.type === lastPassRefresh || (hasProviderForm(provider.type) && provider.actions.includes('config')))) return null
        const operation = actions[action](provider)
        return <Button key={action} aria-label={`${operation.title} ${provider.name}`} variant={operation.danger ? 'danger' : 'secondary'} onClick={() => start(operation)}>{operation.title}</Button>
      })}
    </div>
  )
}

function Entries({ mount }: { mount: Mount }) {
  const entries = useEntries(mount.id)
  if (entries.isPending) return <Loading what="namespace entries" />
  if (entries.isError) return <ProblemAlert error={entries.error} title="Could not load namespace entries" />
  if (!entries.data.length) return <Empty>No namespace entries.</Empty>

  return (
    <ul className={styles.entries}>
      {entries.data.map((entry) => (
        <li key={entry.logicalPath}>
          <strong>{entry.logicalPath}</strong>
          <Facts stacked items={[
            ['Provider path', <code>{entry.providerPath}</code>],
            ...(entry.description ? [['Description', entry.description] as const] : []),
          ]} />
        </li>
      ))}
    </ul>
  )
}

function MountItem({ mount, canChange }: { mount: Mount; canChange: boolean }) {
  const [showEntries, setShowEntries] = useState(false)
  const start = useStartOperation()
  const announce = useAnnounce()
  const queryClient = useQueryClient()
  const refresh = useMutation({
    mutationFn: () => api.post('/api/v1/mounts/{id}/refresh', { path: { id: mount.id } }),
    onSuccess: async (result) => {
      announce(result.complete ? 'Namespace refreshed.' : 'Provider listing was incomplete.')
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: keys.providerMounts(mount.instanceId) }),
        queryClient.invalidateQueries({ queryKey: keys.mountEntries(mount.id) }),
      ])
    },
  })
  const mountActions: Record<Mount['actions'][number], { label: string; run: () => void }> = {
    remove: { label: 'Remove mount', run: () => start(removeMount(mount)) },
    refresh: { label: 'Refresh namespace', run: () => refresh.mutate() },
  }

  return (
    <li className={list.item}>
      <h3>{mount.logicalPath}</h3>
      <Facts items={[
        ['Kind', mount.kind === 'tree' ? 'Tree' : 'Single secret'],
        ['Provider path', mount.basePath ? <code>{mount.basePath}</code> : 'Provider root'],
        ['Entries', mount.entries],
      ]} />
      <div className={list.actions}>
        <Button aria-expanded={showEntries} aria-label={`${showEntries ? 'Hide' : 'Show'} entries for ${mount.logicalPath}`} onClick={() => setShowEntries(!showEntries)}>{showEntries ? 'Hide entries' : 'Show entries'}</Button>
        {canChange ? mount.actions.map((action) => (
          <Button key={action} aria-label={`${action === 'refresh' && refresh.isPending ? 'Refreshing…' : mountActions[action].label} ${mount.logicalPath}`} variant={action === 'remove' ? 'danger' : 'secondary'} disabled={action === 'refresh' && refresh.isPending} onClick={mountActions[action].run}>
            {action === 'refresh' && refresh.isPending ? 'Refreshing…' : mountActions[action].label}
          </Button>
        )) : null}
      </div>
      {refresh.isError ? <ProblemAlert error={refresh.error} /> : null}
      {refresh.data ? <Notice kind={refresh.data.complete ? 'ok' : 'warning'}>{refresh.data.complete ? `Namespace refreshed. Added ${refresh.data.added}, removed ${refresh.data.removed}, changed ${refresh.data.changed}.` : 'The provider returned an incomplete listing. The namespace was kept as it was.'}</Notice> : null}
      {showEntries ? <Entries mount={mount} /> : null}
    </li>
  )
}

export function ProvidersPage() {
  const { id } = useParams()
  const start = useStartOperation()
  const status = useStatus()
  const session = useSession()
  const available = status.data?.capabilities?.providers === true
  const canRead = session.data?.capabilities.includes('admin.read') === true
  const canChange = session.data?.capabilities.includes('admin.decide') === true && status.data?.locked === false
  const providers = useProviders(available && canRead)
  const types = useProviderTypes(available && canRead && !id)
  const provider = providers.data?.find((item) => item.id === id)
  const mounts = useMounts(id ?? '', available && canRead && !!provider)
  usePageTitle(provider?.name ?? 'Providers')

  if (status.isPending) return <><PageHeader title="Providers" /><Loading what="service status" /></>
  if (status.isError) return <><PageHeader title="Providers" /><ProblemAlert error={status.error} /></>
  if (!available || !canRead) return <><PageHeader title="Providers" /><Empty>Provider administration is unavailable in this session.</Empty></>
  if (providers.isPending) return <><PageHeader title="Providers" /><Loading what="providers" /></>
  if (providers.isError) return <><PageHeader title="Providers" /><ProblemAlert error={providers.error} /></>

  if (id) {
    return (
      <>
        <p><Link to="/providers">All providers</Link></p>
        <PageHeader title={provider?.name ?? 'Provider'} />
        <Flash key={id} />
        {provider ? (
          <>
            <ProviderFacts provider={provider} />
            <ProviderActions provider={provider} canChange={canChange} />
            {canChange && provider.actions.includes('config') && !hasProviderForm(provider.type) ? <p>Configure this provider through the API.</p> : null}
            <h2>Mounts</h2>
            {mounts.isPending ? <Loading what="mounts" /> : mounts.isError ? <ProblemAlert error={mounts.error} />
              : mounts.data.length ? <ul className={list.list}>{mounts.data.map((mount) => <MountItem key={mount.id} mount={mount} canChange={canChange} />)}</ul>
                : <Empty>No mounts configured.</Empty>}
          </>
        ) : <Empty>This provider instance is no longer available.</Empty>}
      </>
    )
  }

  return (
    <>
      <PageHeader title="Providers">
        {canChange && types.data?.some(({ type }) => hasProviderForm(type)) ? <Button variant="primary" onClick={() => start(addProvider(types.data))}>Add provider</Button> : null}
      </PageHeader>
      <Flash key="provider-list" />
      {types.isError ? <ProblemAlert error={types.error} title="Could not load provider types" /> : null}
      {types.data?.length === 0 ? <Notice>No provider adapter types are registered.</Notice> : null}
      {types.data?.some(({ type }) => !hasProviderForm(type)) ? <p>Provider types without a configuration form can be configured through the API.</p> : null}
      {providers.data.length ? (
        <ul className={list.list}>
          {providers.data.map((item) => (
            <li key={item.id} className={list.item}>
              <h2><Link to={`/providers/${item.id}`}>{item.name}</Link></h2>
              <ProviderFacts provider={item} />
              <ProviderActions provider={item} canChange={canChange} />
            </li>
          ))}
        </ul>
      ) : <Empty>No provider instances configured.</Empty>}
    </>
  )
}
