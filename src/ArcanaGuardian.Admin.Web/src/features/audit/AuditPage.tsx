import { useState, type FormEvent, type ReactNode } from 'react'
import { Link, NavLink, useSearchParams } from 'react-router-dom'
import { useAuditChanges, useAuditEvents, useAuditGaps, useSession, type AuditFilters } from '../../api/queries'
import type { AuditChange, AuditEvent, AuditGap } from '../../api/types'
import { Badge, Card, Empty, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Field, controlClass } from '../../components/Field'
import { Loading, ProblemAlert } from '../../components/Feedback'
import { DetailsButton, DetailsTable } from '../../components/DetailsTable'
import { Dialog } from '../../components/Dialog'
import { Time } from '../../lib/format'
import { usePageTitle } from '../../lib/usePageTitle'
import styles from './AuditPage.module.css'

type View = 'events' | 'changes' | 'gaps'

const fieldsByView: Record<View, ReadonlyArray<keyof AuditFilters>> = {
  events: ['text', 'type', 'outcome', 'machine', 'grant', 'folder', 'since', 'until', 'last'],
  changes: ['text', 'machine', 'since', 'until', 'last'],
  gaps: ['machine'],
}

const labels: Record<keyof AuditFilters, string> = {
  text: 'Contains text',
  type: 'Kind of event',
  outcome: 'Outcome',
  machine: 'Machine (fingerprint or its start)',
  grant: 'Grant',
  folder: 'Working directory contains',
  since: 'From (ISO 8601)',
  until: 'Until (ISO 8601)',
  last: 'Maximum results (1 to 1000)',
}

const hints: Partial<Record<keyof AuditFilters, string>> = {
  since: 'UTC unless a zone is given, for example 2026-11-09T10:00:00Z.',
  until: 'UTC unless a zone is given.',
  outcome: 'For example approved, denied, started or exited.',
  last: 'Defaults to 100. Increase the limit to see more history.',
}

function filtersFrom(params: URLSearchParams, view: View): AuditFilters {
  const filters: AuditFilters = {}
  for (const name of fieldsByView[view]) {
    const value = params.get(name)
    if (value) filters[name] = value
  }

  return filters
}

export function AuditPage({ view }: { view: View }) {
  const title = view === 'events' ? 'Host events' : view === 'changes' ? 'Authority changes' : 'Numbering gaps'
  usePageTitle('Audit: ' + title)
  const canSearchDetails = useSession().data?.authenticated === true
  const [params, setParams] = useSearchParams()
  const filters = filtersFrom(params, view)

  return (
    <>
      <PageHeader title="Audit" />
      <nav aria-label="Audit views" className={styles.tabs}>
        <NavLink to="/audit" end>
          Host events
        </NavLink>
        <NavLink to="/audit/changes">Authority changes</NavLink>
        <NavLink to="/audit/gaps">Numbering gaps</NavLink>
      </nav>
      <h2>{title}</h2>
      {view === 'events' ? <p>Do not put secrets in command-line arguments: they may be recorded here.</p> : view === 'gaps' ? <p>A gap is a reason to look closer, not proof of tampering.</p> : null}
      <AuditSearch key={view + ':' + params.toString()} view={view} title={title} params={params} onSearch={setParams} canSearchDetails={canSearchDetails} />
      {view === 'events' ? <Events key={params.toString()} filters={filters} />
        : view === 'changes' ? <Changes key={params.toString()} filters={filters} />
          : <Gaps key={params.toString()} machine={filters.machine ?? ''} />}
    </>
  )
}

const ranges = [
  { id: 'hour', label: 'Past hour', hours: 1 },
  { id: 'day', label: 'Past 24 hours', hours: 24 },
  { id: 'week', label: 'Past 7 days', hours: 168 },
]

function AuditSearch({ view, title, params, onSearch, canSearchDetails }: {
  view: View; title: string; params: URLSearchParams; canSearchDetails: boolean; onSearch: (params: URLSearchParams) => void
}) {
  const appliedRange = ranges.find(option => option.id === params.get('range'))
  const [range, setRange] = useState(appliedRange?.id ?? (params.has('since') || params.has('until') ? 'custom' : ''))
  const extra = fieldsByView[view].filter(name => !['text', 'since', 'until'].includes(name))
  const activeCount = extra.filter(name => params.has(name)).length

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const next = new URLSearchParams()
    for (const name of fieldsByView[view]) {
      const value = String(data.get(name) ?? '').trim()
      if (value) next.set(name, value)
    }

    const preset = ranges.find(option => option.id === range)
    if (view !== 'gaps' && preset) {
      next.set('range', preset.id)
      const now = Date.now()
      next.set('since', new Date(now - preset.hours * 60 * 60 * 1000).toISOString())
      next.set('until', new Date(now).toISOString())
    }
    onSearch(next)
  }

  return (
    <Card>
      <form onSubmit={submit} className={styles.form} role="search" aria-label={'Search ' + title.toLowerCase()}>
        <div className={styles.primary}>
          {view === 'gaps' ? <AuditField name="machine" params={params} /> : (
            <>
              {canSearchDetails ? <AuditField name="text" params={params} /> : null}
              <Field label="Time range">
                {control => <select {...control} className={controlClass} value={range} onChange={event => setRange(event.target.value)}>
                  <option value="">Any time</option>
                  {ranges.map(option => <option key={option.id} value={option.id}>{option.label}</option>)}
                  <option value="custom">Custom range</option>
                </select>}
              </Field>
            </>
          )}
          <div className={styles.submit}>
            <Button variant="primary" type="submit">Search</Button>
            {params.size > 0 ? <Button type="button" onClick={() => onSearch(new URLSearchParams())}>Clear filters</Button> : null}
          </div>
        </div>
        {view !== 'gaps' && range === 'custom' ? (
          <div className={styles.extraFields}>
            <AuditField name="since" params={params} />
            <AuditField name="until" params={params} />
          </div>
        ) : null}
        {view !== 'gaps' && extra.length > 0 ? (
          <details className={styles.extra} open={activeCount > 0}>
            <summary>More filters{activeCount > 0 ? ' (' + activeCount + ' active)' : ''}</summary>
            <div className={styles.extraFields}>{extra.map(name => <AuditField key={name} name={name} params={params} />)}</div>
          </details>
        ) : null}
      </form>
    </Card>
  )
}

function AuditField({ name, params }: { name: keyof AuditFilters; params: URLSearchParams }) {
  return (
    <Field label={labels[name]} hint={hints[name]}>
      {control => name === 'type' ? (
        <select {...control} name={name} className={controlClass} defaultValue={params.get(name) ?? ''}>
          <option value="">Any</option>
          <option value="authorization">Authorization</option>
          <option value="launch">Launch</option>
          <option value="execution">Execution</option>
          <option value="admin">Admin</option>
        </select>
      ) : (
        <input {...control} name={name} type={name === 'text' ? 'search' : 'text'} className={controlClass} defaultValue={params.get(name) ?? ''}
          autoComplete="off" spellCheck={false} inputMode={name === 'last' ? 'numeric' : undefined} />
      )}
    </Field>
  )
}

function Count({ n, singular, plural }: { n: number; singular: string; plural: string }) {
  return (
    <p role="status" className={styles.count}>
      {n === 0 ? `No ${plural} match these filters.` : n === 1 ? `1 ${singular} found.` : `Showing ${n} ${plural}.`}
    </p>
  )
}

const passkeyRoles = [
  ['key', 'Passkey used'],
  ['sessionKey', 'Session passkey'],
  ['grantApproved', 'Grant approved by'],
  ['grantChanged', 'Grant changed by'],
  ['unlock', 'Authority unlocked by'],
] as const

function auditMetadata(metadata: Record<string, string> = {}): Array<readonly [string, ReactNode]> {
  const fields = new Set<string>()
  const items: Array<readonly [string, ReactNode]> = []
  for (const [prefix, role] of passkeyRoles) {
    const [idField, nameField, adminField] = [prefix + 'Id', prefix + 'Name', prefix + 'Admin'] as const
    const id = metadata[idField]
    const name = metadata[nameField]
    const admin = metadata[adminField]
    if (!id || !name || (admin !== 'true' && admin !== 'false')) continue

    items.push([role, <span title={id}>{name} ({admin === 'true' ? 'admin' : 'approval'}, <code>{id.slice(0, 8)}</code>)</span>])
    fields.add(idField)
    fields.add(nameField)
    fields.add(adminField)
  }

  if (items.length === 0) items.push(['Passkey used', 'None recorded'])

  return [
    ...items,
    ...Object.entries(metadata)
      .filter(([name]) => !fields.has(name))
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([name, value]): [string, string] => ['Metadata: ' + name, value]),
  ]
}

function machineLabel(machine: string | null) {
  return machine ? machine.slice(0, 9) + (machine.length > 9 ? '\u2026' : '') : 'None'
}

function machineLink(path: string, machine: string | null, close: () => void) {
  return machine ? <Link onClick={close} to={path + '?' + new URLSearchParams({ machine })}>{machine}</Link> : 'None'
}

function EventOutcome({ outcome }: { outcome: string }) {
  return <Badge tone={outcome === 'denied' || outcome === 'failed' ? 'bad' : 'neutral'}>{outcome}</Badge>
}

function EventDetails({ event, close }: { event: AuditEvent; close: () => void }) {
  return (
    <Dialog title={event.type + ': ' + event.outcome} onCancel={close} footer={<Button onClick={close}>Close</Button>}>
      <Facts items={[
        ['Occurred', <Time value={event.time} />],
        ['Received', <Time value={event.received} />],
        ['Machine', machineLink('/audit', event.machine, close)],
        ...(event.program ? [['Program', [event.program, ...event.arguments].join(' ')] as const] : []),
        ...(event.folder ? [['Folder', event.folder] as const] : []),
        ...(event.reason ? [['Reason', event.reason] as const] : []),
        ...(event.grantId ? [['Grant', <Link to={'/audit?' + new URLSearchParams({ grant: event.grantId })} onClick={close}>{event.grantId}</Link>] as const] : []),
        ...(event.exitCode !== null ? [['Exit code', String(event.exitCode)] as const] : []),
        ['Sequence', String(event.sequence)],
        ...auditMetadata(event.metadata),
      ]} />
    </Dialog>
  )
}

function Events({ filters }: { filters: AuditFilters }) {
  const events = useAuditEvents(filters, true)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  if (events.isPending) return <Loading what="events" />
  if (events.isError) return <ProblemAlert error={events.error} title="The events could not be searched" />
  const selected = events.data.find(event => event.eventId === selectedId)

  return (
    <>
      <Count n={events.data.length} singular="event" plural="events" />
      {events.data.length > 0 ? (
        <DetailsTable label="Host events" columns={['Event', 'Time', 'Machine', 'Outcome']}>
          {events.data.map(event => (
            <tr key={event.eventId}>
              <th scope="row">
                <DetailsButton title={event.type} subtitle={event.program?.split(/[\\/]/).at(-1) || undefined}
                  description={'View ' + event.outcome + ' event ' + event.sequence} onClick={() => setSelectedId(event.eventId)} />
              </th>
              <td><Time value={event.time} /></td>
              <td title={event.machine ?? undefined}>{machineLabel(event.machine)}</td>
              <td><EventOutcome outcome={event.outcome} /></td>
            </tr>
          ))}
        </DetailsTable>
      ) : null}
      {selected ? <EventDetails event={selected} close={() => setSelectedId(null)} /> : null}
    </>
  )
}

function Changes({ filters }: { filters: AuditFilters }) {
  const changes = useAuditChanges(filters, true)
  const [selectedId, setSelectedId] = useState<AuditChange['id'] | null>(null)
  if (changes.isPending) return <Loading what="changes" />
  if (changes.isError) return <ProblemAlert error={changes.error} title="The changes could not be searched" />
  const selected = changes.data.find(change => change.id === selectedId)
  const close = () => setSelectedId(null)

  return (
    <>
      <Count n={changes.data.length} singular="change" plural="changes" />
      {changes.data.length > 0 ? (
        <DetailsTable label="Authority changes" columns={['Change', 'Time', 'Actor', 'Machine']}>
          {changes.data.map(change => (
            <tr key={change.id}>
              <th scope="row"><DetailsButton title={change.event} description={'View change ' + change.id} onClick={() => setSelectedId(change.id)} /></th>
              <td><Time value={change.time} /></td>
              <td>{change.actor}</td>
              <td title={change.machine ?? undefined}>{machineLabel(change.machine)}</td>
            </tr>
          ))}
        </DetailsTable>
      ) : null}
      {selected ? (
        <Dialog title={selected.event} onCancel={close} footer={<Button onClick={close}>Close</Button>}>
          <Facts items={[
            ['Time', <Time value={selected.time} />],
            ['By', selected.actor],
            ['Machine', machineLink('/audit/changes', selected.machine, close)],
            ['Detail', selected.detail],
            ...auditMetadata(selected.metadata),
          ]} />
        </Dialog>
      ) : null}
    </>
  )
}

function GapStatus({ gap }: { gap: AuditGap }) {
  return <Badge tone={gap.resolved ? 'ok' : 'warn'}>{gap.resolved ? 'Resolved' : 'Open'}</Badge>
}

function Gaps({ machine }: { machine: string }) {
  const gaps = useAuditGaps(machine, true)
  const [selectedId, setSelectedId] = useState<AuditGap['id'] | null>(null)
  if (gaps.isPending) return <Loading what="gaps" />
  if (gaps.isError) return <ProblemAlert error={gaps.error} title="The gaps could not be listed" />
  if (gaps.data.length === 0) return <Empty>No numbering anomaly matches this filter.</Empty>
  const selected = gaps.data.find(gap => gap.id === selectedId)
  const close = () => setSelectedId(null)

  return (
    <>
      <Count n={gaps.data.length} singular="gap" plural="gaps" />
      <DetailsTable label="Numbering gaps" columns={['Numbers', 'Detected', 'Machine', 'Status']}>
        {gaps.data.map(gap => (
          <tr key={gap.id}>
            <th scope="row"><DetailsButton title={gap.from + ' to ' + gap.to} description={'View gap ' + gap.id} onClick={() => setSelectedId(gap.id)} /></th>
            <td><Time value={gap.detected} /></td>
            <td title={gap.machine}>{machineLabel(gap.machine)}</td>
            <td><GapStatus gap={gap} /></td>
          </tr>
        ))}
      </DetailsTable>
      {selected ? (
        <Dialog title={'Numbers ' + selected.from + ' to ' + selected.to} onCancel={close} footer={<Button onClick={close}>Close</Button>}>
          <Facts items={[
            ['Machine', machineLink('/audit/gaps', selected.machine, close)],
            ['Kind', selected.kind],
            ['Status', <GapStatus gap={selected} />],
            ['Detected', <Time value={selected.detected} />],
            ['Resolved', <Time value={selected.resolved} />],
          ]} />
        </Dialog>
      ) : null}
    </>
  )
}
