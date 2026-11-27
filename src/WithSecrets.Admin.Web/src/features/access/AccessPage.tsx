import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import { keys, useApprovals, useGrants, useSession, useStatus } from '../../api/queries'
import type { ApprovalQueue, Grant } from '../../api/types'
import { Badge, Empty, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { DetailsButton, DetailsLink, DetailsTable } from '../../components/DetailsTable'
import { Dialog } from '../../components/Dialog'
import { SplitButton } from '../../components/SplitButton'
import { Loading, ProblemAlert } from '../../components/Feedback'
import list from '../../components/List.module.css'
import { Time } from '../../lib/format'
import { usePageTitle } from '../../lib/usePageTitle'
import { changeGrantEnd, revokeGrant, type OperationDef, type Prepared } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'
import { usePollInterval } from '../authorization/poll'
import { ALWAYS, ApprovalDialog, timeLabel } from './ApprovalDialog'
import styles from './AccessPage.module.css'

const labels: Record<Grant['actions'][number], string> = { extend: 'Extend', renew: 'Renew', revoke: 'Revoke', replace: 'Allow repeat runs' }
const builders: Record<Grant['actions'][number], (grant: Grant) => OperationDef> = {
  extend: (grant) => changeGrantEnd(grant, 'extend'),
  renew: (grant) => changeGrantEnd(grant, 'renew'),
  revoke: revokeGrant,
  replace: (grant) => changeGrantEnd(grant, 'replace'),
}

function repeatGrant(grant: Grant, minutes: number): OperationDef {
  const parameters: Prepared['parameters'] = minutes === ALWAYS ? { id: grant.id, indefinite: true } : { id: grant.id, minutes }
  return {
    key: 'grant-extend', title: 'Allow repeat runs', confirmLabel: 'Confirm extension', promptOnOpen: true,
    prepare: () => ({
      operation: 'grant-extend',
      parameters,
      summary: `Allow repeat runs ${minutes === ALWAYS ? 'at any time' : 'for ' + timeLabel(minutes)} on grant ${grant.id}.`,
      done: `Extended grant ${grant.id} ${minutes === ALWAYS ? 'with no end' : 'for ' + timeLabel(minutes)}.`,
    }),
  }
}

/**
 * What machines may run: the run requests that wait for a person first, then the grants (standing approvals) that already exist. One screen, because a grant is
 * a request that was approved for a while. Both lists follow along by themselves: a request that arrives, or a grant made a moment after its approval, shows up.
 */
export function AccessPage() {
  usePageTitle('Access')
  const { requestId } = useParams()
  const navigate = useNavigate()
  const poll = usePollInterval()
  const session = useSession()
  const signedIn = session.data?.authenticated === true
  const approvals = useApprovals(signedIn, poll * 3)
  const grants = useGrants(true, poll * 3)
  const visibleGrants = grants.data?.filter(grant => grant.state !== 'expired')
  const [selectedGrantId, setSelectedGrantId] = useState<string | null>(null)
  const selectedGrant = visibleGrants?.find(grant => grant.id === selectedGrantId)
  const status = useStatus()
  const canChange = session.data?.capabilities.includes('grants.decide') === true
  const start = useStartOperation()

  return (
    <>
      <PageHeader title="Access" />
      {requestId && !signedIn ? <p><Link to="/sign-in" state={{ returnTo: `/access/${encodeURIComponent(requestId)}` }}>Sign in to review this request</Link></p> : null}

      {signedIn ? <section className={styles.section} aria-labelledby="waiting-heading">
        <h2 id="waiting-heading">Waiting for you</h2>
        {approvals.isPending ? <Loading what="the requests" /> : null}
        {approvals.isError ? <ProblemAlert error={approvals.error} title="The requests could not be read" /> : null}
        {approvals.data?.items.length === 0 ? <Empty>No run request is waiting.</Empty> : null}
        {approvals.data && approvals.data.items.length > 0 ? (
          <PendingRequests queue={approvals.data} receivedAt={approvals.dataUpdatedAt} />
        ) : null}
      </section> : null}

      <section className={styles.section} aria-labelledby="grants-heading">
        <h2 id="grants-heading">Grants</h2>
        {grants.isPending ? <Loading what="grants" /> : null}
        {grants.isError ? <ProblemAlert error={grants.error} title="The grants could not be listed" /> : null}
        {visibleGrants?.length === 0 ? <Empty>No grants. A grant lets a machine run a program without asking each time.</Empty> : null}
        {visibleGrants && visibleGrants.length > 0 ? (
          <DetailsTable label="Grants" columns={['Command', 'Status', 'Ends']}>
            {visibleGrants.map(grant => (
              <tr key={grant.id}>
                <th scope="row">
                  <DetailsButton title={grantProgram(grant)} subtitle={grant.machineName ?? grant.fingerprint}
                    description={'View grant ' + grant.id} onClick={() => setSelectedGrantId(grant.id)} />
                </th>
                <td><GrantStatus grant={grant} /></td>
                <td><GrantEnd grant={grant} /></td>
              </tr>
            ))}
          </DetailsTable>
        ) : null}
      </section>

      {selectedGrant && !requestId ? (
        <GrantDetails grant={selectedGrant} reviewOpen={status.data?.reviewOpen === true} poll={poll * 3} canChange={canChange} signedIn={signedIn} adminSession={session.data?.scope === 'admin'}
          onClose={() => setSelectedGrantId(null)} onAction={operation => {
            setSelectedGrantId(null)
            start(operation)
          }} />
      ) : null}
      {requestId && signedIn ? <ApprovalDialog key={requestId} requestId={requestId} onClose={() => navigate('/access')} /> : null}
    </>
  )
}

function PendingRequests({ queue, receivedAt }: { queue: ApprovalQueue; receivedAt: number }) {
  const [now, setNow] = useState(Date.now)
  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(interval)
  }, [])

  const serverNow = Date.parse(queue.serverTime) + Math.max(0, now - receivedAt)
  const requests = [...queue.items].sort((a, b) => Date.parse(a.expiresAt) - Date.parse(b.expiresAt))

  return (
    <DetailsTable label="Run requests" columns={['Command', 'Time left']}>
      {requests.map(item => {
        const machine = item.machine.friendlyName ?? item.machine.hostName
        const command = item.scriptName || programName(item.program)
        const minutes = Math.ceil((Date.parse(item.expiresAt) - serverNow) / 60_000)
        const timeLeft = minutes <= 0 ? 'Expired' : minutes > 60
          ? Math.floor(minutes / 60) + 'h ' + (minutes % 60) + 'm'
          : minutes + ' min'
        return (
          <tr key={item.requestId}>
            <th scope="row">
              <DetailsLink to={'/access/' + encodeURIComponent(item.requestId)} title={command} subtitle={machine}
                description="Review request" opensDialog />
            </th>
            <td><time dateTime={item.expiresAt} title={new Date(item.expiresAt).toLocaleString()}>{timeLeft}</time></td>
          </tr>
        )
      })}
    </DetailsTable>
  )
}

function grantProgram(grant: Grant) {
  return programName(grant.program)
}

function programName(program: string) {
  return program.split(/[\\/]/).at(-1) || program
}

function GrantStatus({ grant }: { grant: Grant }) {
  if (grant.state === 'active' && !grant.verified) return <Badge tone="warn">Unverified</Badge>
  return <Badge tone={grant.state === 'active' ? 'ok' : grant.state === 'revoked' ? 'bad' : 'neutral'}>
    {grant.state === 'consumed' ? 'Used once' : grant.state}
  </Badge>
}

function GrantEnd({ grant }: { grant: Grant }) {
  if (grant.state === 'consumed' || grant.state === 'invalidated') return <><span aria-hidden="true">None</span><span className="visually-hidden">No expiry applies</span></>
  if (grant.revoked) return <Time value={grant.revoked} />
  return grant.expires ? <Time value={grant.expires} /> : <>No end</>
}

function GrantDetails({ grant, reviewOpen, poll, canChange, signedIn, adminSession, onClose, onAction }: {
  grant: Grant; reviewOpen: boolean; poll: number; canChange: boolean; signedIn: boolean; adminSession: boolean; onClose: () => void; onAction: (operation: OperationDef) => void
}) {
  const ended = grant.status === 'revoked' || grant.status === 'invalidated'
  return (
    <Dialog title={'Grant for ' + grantProgram(grant)} onCancel={onClose} footer={
      <>
        <Button onClick={onClose}>Close</Button>
        {canChange && grant.actions.map((action) => action === 'extend' && grant.state === 'consumed' ? (
          <SplitButton key={action} label="Allow repeat runs" menuLabel={'Allow repeat runs for grant ' + grant.id}
            items={grant.repeatTimes.map(minutes => ({
              label: timeLabel(minutes),
              onSelect: () => onAction(repeatGrant(grant, minutes)),
            }))} />
        ) : (
          <Button key={action} variant={action === 'revoke' ? 'dangerOutline' : 'secondary'} onClick={() => onAction(action === 'revoke' ? revokeGrant(grant, adminSession) : builders[action](grant))}>
            {labels[action]}{' '}<span className="visually-hidden">grant {grant.id}</span>
          </Button>
        ))}
      </>
    }>
      <Facts items={[
        ['Machine', grant.machineName ?? grant.fingerprint],
        ['Program', <code key="program">{grant.program}</code>],
        ['Secrets', grant.secretNames],
        ['Folder', grant.workingDirectory],
        ['Status', <GrantStatus key="status" grant={grant} />],
        ...(grant.consumed ? ([['Used', <Time key="used" value={grant.consumed} />]] as const) : []),
        ...(grant.state === 'active' ? ([['Ends', <GrantEnd key="end" grant={grant} />]] as const) : []),
        ...(grant.revoked ? ([['Revoked', <Time key="r" value={grant.revoked} />]] as const) : []),
        ['Approved by', grant.approvedBy],
        ['Created', <Time key="c" value={grant.created} />],
        ['Grant ID', <code key="id">{grant.id}</code>],
        ...(grant.replaces ? ([['Replaces', grant.replaces]] as const) : []),
      ]} />
      {!grant.verified && !ended ? <p>This grant is not verified and is not used.</p> : null}
      <div className={list.actions}>
        <Link to={'/audit?' + new URLSearchParams({ grant: grant.id })}>Events for this grant</Link>
        <Link to={'/audit/changes?' + new URLSearchParams({ machine: grant.fingerprint })}>Changes to this machine</Link>
      </div>
      {signedIn ? <GrantReview grant={grant} reviewOpen={reviewOpen} poll={poll} /> : null}
    </Dialog>
  )
}

function GrantReview({ grant, reviewOpen, poll }: { grant: Grant; reviewOpen: boolean; poll: number }) {
  const [expanded, setExpanded] = useState(false)
  const ended = grant.status === 'revoked' || grant.status === 'invalidated'
  if (ended) return <p>No review text is kept for an ended grant.</p>
  return (
    <div className={styles.review}>
      <Button variant="secondary" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>
        {expanded ? 'Hide review' : 'Review'}<span className="visually-hidden"> grant {grant.id}</span>
      </Button>
      {expanded ? <ReviewText id={grant.id} reviewOpen={reviewOpen} poll={poll} /> : null}
    </div>
  )
}

function ReviewText({ id, reviewOpen, poll }: { id: string; reviewOpen: boolean; poll: number }) {
  const query = useQuery({
    queryKey: [...keys.grants, id, 'review', reviewOpen],
    queryFn: () => api.get('/api/v1/grants/{id}/review', { path: { id } }),
    gcTime: 0,
    staleTime: 0,
    refetchInterval: poll,
  })

  if (query.isPending) return <Loading what="review text" />
  if (query.isError) return <ProblemAlert error={query.error} title="Review text could not be read" />
  if (query.data.state === 'none') return <p>No review text is available for this grant.</p>
  if (query.data.state !== 'open' || !reviewOpen) return <p>Review text opens when an administrator unlocks the authority with an admin passkey.</p>

  return <pre className={styles.reviewText}>{query.data.text}</pre>
}
