import type { FormEvent } from 'react'
import { Link, NavLink, useSearchParams } from 'react-router-dom'
import { useAuditChanges, useAuditEvents, useAuditGaps, type AuditFilters } from '../../api/queries'
import { Badge, Card, Empty, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Field, controlClass } from '../../components/Field'
import { Loading, ProblemAlert } from '../../components/Feedback'
import list from '../../components/List.module.css'
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
  last: 'Default 100, maximum 1000. A limited result is not the complete history.',
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
  const [params, setParams] = useSearchParams()
  const filters = filtersFrom(params, view)

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const next = new URLSearchParams()
    for (const name of fieldsByView[view]) {
      const value = String(data.get(name) ?? '').trim()
      if (value) next.set(name, value)
    }
    setParams(next)
  }

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
      <p>
        {view === 'events'
          ? 'What hosts reported: authorization, launch and execution outcomes, and administrative changes. Credential-shaped values are masked before storage when recognized; bare secret arguments may not be recognized. Avoid putting secrets in command-line arguments. Metadata contains descriptive names and fingerprints, not secret values.'
          : view === 'changes'
            ? 'What changed at the authority: administrator operations and machine and grant changes.'
            : 'Sequence diagnostics for a machine, including missing or reused numbers and a new outbox epoch. An anomaly is a reason to investigate, not proof of tampering.'}
      </p>
      <Card>
        <form key={params.toString()} onSubmit={submit} className={styles.form} role="search" aria-label={'Search ' + title.toLowerCase()}>
          {fieldsByView[view].map((name) => (
            <Field key={name} label={labels[name]} hint={hints[name]}>
              {(control) =>
                name === 'type' ? (
                  <select {...control} name={name} className={controlClass} defaultValue={params.get(name) ?? ''}>
                    <option value="">Any</option>
                    <option value="authorization">authorization</option>
                    <option value="launch">launch</option>
                    <option value="execution">execution</option>
                    <option value="admin">admin</option>
                  </select>
                ) : (
                  <input {...control} name={name} type="text" className={controlClass} defaultValue={params.get(name) ?? ''} autoComplete="off" spellCheck={false} inputMode={name === 'last' ? 'numeric' : undefined} />
                )
              }
            </Field>
          ))}
          <div className={styles.submit}>
            <Button variant="primary" type="submit">
              Search
            </Button>
            {params.toString().length > 0 ? (
              <Button variant="secondary" type="button" onClick={() => setParams(new URLSearchParams())}>
                Clear filters
              </Button>
            ) : null}
          </div>
        </form>
      </Card>
      {view === 'events' ? <Events filters={filters} /> : view === 'changes' ? <Changes filters={filters} /> : <Gaps machine={filters.machine ?? ''} />}
    </>
  )
}

function Count({ n, singular, plural }: { n: number; singular: string; plural: string }) {
  return (
    <p role="status" className={styles.count}>
      {n === 0 ? `No ${plural} match these filters.` : n === 1 ? `1 ${singular} found.` : `Showing ${n} ${plural}.`}
    </p>
  )
}

function Events({ filters }: { filters: AuditFilters }) {
  const events = useAuditEvents(filters, true)
  if (events.isPending) return <Loading what="events" />
  if (events.isError) return <ProblemAlert error={events.error} title="The events could not be searched" />

  return (
    <>
      <Count n={events.data.length} singular="event" plural="events" />
      <ul className={[list.list, list.compact].join(' ')} aria-label="Host events">
        {events.data.map((event) => (
          <li key={event.eventId} className={list.item}>
            <div className={list.itemHeader}>
              <h3>
                {event.type}: {event.outcome}
              </h3>
              <Badge tone={event.outcome === 'denied' || event.outcome === 'failed' ? 'bad' : 'neutral'}>{event.outcome}</Badge>
            </div>
            <Facts
              items={[
                ['Occurred', <Time key="occurred" value={event.time} />],
                ['Received', <Time key="received" value={event.received} />],
                ['Machine', event.machine ? <Link key="machine" to={`/audit?${new URLSearchParams({ machine: event.machine }).toString()}`}>{event.machine}</Link> : 'none'],
                ['Program', event.program || 'none'],
                ['Arguments', event.arguments.length ? event.arguments.join(' ') : 'none'],
                ['Working directory', event.folder || 'none'],
                ['Reason', event.reason || 'none'],
                ['Grant', event.grantId ? <Link key="grant" to={`/audit?${new URLSearchParams({ grant: event.grantId }).toString()}`}>{event.grantId}</Link> : 'none'],
                ['Exit code', event.exitCode === null ? 'none' : String(event.exitCode)],
                ['Sequence', String(event.sequence)],
                // The metadata is data the host signed (names and fingerprints): shown as plain text, never as markup.
                ...Object.entries(event.metadata)
                  .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
                  .map(([name, value]): [string, string] => ['Metadata: ' + name, value]),
              ]}
            />
          </li>
        ))}
      </ul>
    </>
  )
}

function Changes({ filters }: { filters: AuditFilters }) {
  const changes = useAuditChanges(filters, true)
  if (changes.isPending) return <Loading what="changes" />
  if (changes.isError) return <ProblemAlert error={changes.error} title="The changes could not be searched" />

  return (
    <>
      <Count n={changes.data.length} singular="change" plural="changes" />
      <ul className={[list.list, list.compact].join(' ')} aria-label="Authority changes">
        {changes.data.map((change) => (
          <li key={change.id} className={list.item}>
            <div className={list.itemHeader}>
              <h3>{change.event}</h3>
              <Time value={change.time} />
            </div>
            <Facts
              items={[
                ['By', change.actor],
                ['Machine', change.machine ? <Link key="machine" to={`/audit/changes?${new URLSearchParams({ machine: change.machine }).toString()}`}>{change.machine}</Link> : 'none'],
                ['Detail', change.detail],
              ]}
            />
          </li>
        ))}
      </ul>
    </>
  )
}

function Gaps({ machine }: { machine: string }) {
  const gaps = useAuditGaps(machine, true)
  if (gaps.isPending) return <Loading what="gaps" />
  if (gaps.isError) return <ProblemAlert error={gaps.error} title="The gaps could not be listed" />
  if (gaps.data.length === 0) return <Empty>No numbering anomaly matches this filter.</Empty>

  return (
    <>
      <Count n={gaps.data.length} singular="gap" plural="gaps" />
      <ul className={[list.list, list.compact].join(' ')} aria-label="Numbering gaps">
        {gaps.data.map((gap) => (
          <li key={gap.id} className={list.item}>
            <div className={list.itemHeader}>
              <h3>
                Numbers {gap.from} to {gap.to}
              </h3>
              <Badge tone={gap.resolved ? 'ok' : 'warn'}>{gap.resolved ? 'resolved' : 'open'}</Badge>
            </div>
            <Facts
              items={[
                ['Machine', <Link key="machine" to={`/audit/gaps?${new URLSearchParams({ machine: gap.machine }).toString()}`}>{gap.machine}</Link>],
                ['Kind', gap.kind],
                ['Detected', <Time key="d" value={gap.detected} />],
                ['Resolved', <Time key="r" value={gap.resolved} />],
              ]}
            />
          </li>
        ))}
      </ul>
    </>
  )
}
