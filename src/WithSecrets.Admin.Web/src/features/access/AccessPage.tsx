import { Link, useNavigate, useParams } from 'react-router-dom'
import { useApprovals, useGrants } from '../../api/queries'
import type { Grant } from '../../api/types'
import { Badge, Empty, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import button from '../../components/Button.module.css'
import { Flash } from '../../components/Flash'
import { Loading, ProblemAlert } from '../../components/Feedback'
import list from '../../components/List.module.css'
import { Time } from '../../lib/format'
import { usePageTitle } from '../../lib/usePageTitle'
import { changeGrantEnd, revokeGrant, type OperationDef } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'
import { usePollInterval } from '../authorization/poll'
import { ApprovalDialog } from './ApprovalDialog'
import styles from './AccessPage.module.css'

const labels: Record<Grant['actions'][number], string> = { extend: 'Extend', renew: 'Renew', revoke: 'Revoke' }
const builders: Record<Grant['actions'][number], (grant: Grant) => OperationDef> = {
  extend: (grant) => changeGrantEnd(grant, 'extend'),
  renew: (grant) => changeGrantEnd(grant, 'renew'),
  revoke: revokeGrant,
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
  const approvals = useApprovals(true, poll * 3)
  const grants = useGrants(true, poll * 3)
  const start = useStartOperation()

  return (
    <>
      <PageHeader title="Access" />
      {/* Opening a request starts over: what the last action said is not about this one. */}
      <Flash key={requestId ?? 'list'} />

      <section className={styles.section} aria-labelledby="waiting-heading">
        <h2 id="waiting-heading">Waiting for you</h2>
        {approvals.isPending ? <Loading what="the requests" /> : null}
        {approvals.isError ? <ProblemAlert error={approvals.error} title="The requests could not be read" /> : null}
        {approvals.data?.items.length === 0 ? <Empty>No run request is waiting.</Empty> : null}
        {approvals.data && approvals.data.items.length > 0 ? (
          <ul className={list.list} aria-label="Run requests">
            {approvals.data.items.map((item) => (
              <li key={item.requestId} className={list.item}>
                <div className={list.itemHeader}>
                  <h3>{item.machine.friendlyName ?? item.machine.hostName}</h3>
                </div>
                <Facts
                  items={[
                    ['Runs', <code key="program">{item.program}</code>],
                    ['Secrets', item.secretNames.join(', ')],
                    ['Reason', item.reason],
                    ['Expires', <Time key="expires" value={item.expiresAt} />],
                  ]}
                />
                <p>
                  <Link className={[button.button, button.primary].join(' ')} to={'/access/' + encodeURIComponent(item.requestId)}>
                    Review <span className="visually-hidden">{item.program} from {item.machine.friendlyName ?? item.machine.hostName}</span>
                  </Link>
                </p>
              </li>
            ))}
          </ul>
        ) : null}
      </section>

      <section className={styles.section} aria-labelledby="grants-heading">
        <h2 id="grants-heading">Grants</h2>
        {grants.isPending ? <Loading what="grants" /> : null}
        {grants.isError ? <ProblemAlert error={grants.error} title="The grants could not be listed" /> : null}
        {grants.data?.length === 0 ? <Empty>No grants. A grant lets a machine run a program without asking each time.</Empty> : null}
        {grants.data && grants.data.length > 0 ? (
          <ul className={list.list} aria-label="Grants">
            {grants.data.map((grant) => (
              <li key={grant.id} className={list.item}>
                <div className={list.itemHeader}>
                  <h3>
                    <span className={list.mono}>{grant.id}</span>
                  </h3>
                  <Badge tone={grant.state === 'active' ? 'ok' : grant.state === 'revoked' ? 'bad' : 'neutral'}>{grant.state}</Badge>
                </div>
              <Facts
                items={[
                  ['Machine', grant.machineName ?? grant.fingerprint],
                  [
                    'History',
                    <span key="history">
                      <Link to={`/audit?${new URLSearchParams({ grant: grant.id }).toString()}`}>Events for this grant</Link>
                      {' · '}
                      <Link to={`/audit/changes?${new URLSearchParams({ machine: grant.fingerprint }).toString()}`}>Changes to this machine</Link>
                    </span>,
                  ],
                  ['Secrets', grant.secretNames],
                  ['Program', grant.program],
                  ['Folder', grant.workingDirectory],
                  ['Approved by', grant.approvedBy],
                  ['Ends', grant.expires ? <Time key="e" value={grant.expires} /> : grant.ends],
                  ['Created', <Time key="c" value={grant.created} />],
                  ...(grant.revoked ? ([['Revoked', <Time key="r" value={grant.revoked} />]] as const) : []),
                ]}
              />
              {grant.actions.length > 0 ? (
                <div className={list.actions}>
                  {grant.actions.map((action) => (
                    <Button key={action} variant={action === 'revoke' ? 'danger' : 'secondary'} onClick={() => start(builders[action](grant))}>
                      {labels[action]}
                      <span className="visually-hidden"> grant {grant.id}</span>
                    </Button>
                  ))}
                </div>
              ) : null}
            </li>
            ))}
          </ul>
        ) : null}
      </section>

      {requestId ? <ApprovalDialog key={requestId} requestId={requestId} onClose={() => navigate('/access')} /> : null}
    </>
  )
}
