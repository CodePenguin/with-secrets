import { Link } from 'react-router-dom'
import { useGrants } from '../../api/queries'
import type { Grant } from '../../api/types'
import { Badge, Empty, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Loading, ProblemAlert } from '../../components/Feedback'
import list from '../../components/List.module.css'
import { Time } from '../../lib/format'
import { usePageTitle } from '../../lib/usePageTitle'
import { changeGrantEnd, revokeGrant, type OperationDef } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'

const labels: Record<Grant['actions'][number], string> = { extend: 'Extend', renew: 'Renew', revoke: 'Revoke' }
const builders: Record<Grant['actions'][number], (grant: Grant) => OperationDef> = {
  extend: (grant) => changeGrantEnd(grant, 'extend'),
  renew: (grant) => changeGrantEnd(grant, 'renew'),
  revoke: revokeGrant,
}

export function GrantsPage() {
  usePageTitle('Grants')
  const grants = useGrants(true)
  const start = useStartOperation()

  return (
    <>
      <PageHeader title="Grants" />
      <p>A grant lets one machine run one program with named secrets without asking each time. Only the names of the secrets are shown, never a value.</p>
      {grants.isPending ? <Loading what="grants" /> : null}
      {grants.isError ? <ProblemAlert error={grants.error} title="The grants could not be listed" /> : null}
      {grants.data?.length === 0 ? <Empty>There are no grants.</Empty> : null}
      {grants.data && grants.data.length > 0 ? (
        <ul className={list.list} aria-label="Grants">
          {grants.data.map((grant) => (
            <li key={grant.id} className={list.item}>
              <div className={list.itemHeader}>
                <h2>
                  <span className={list.mono}>{grant.id}</span>
                </h2>
                <Badge tone={grant.state === 'active' ? 'ok' : grant.state === 'revoked' ? 'bad' : 'neutral'}>{grant.state}</Badge>
              </div>
              <Facts
                items={[
                  ['Machine', grant.machineName ?? grant.fingerprint],
                  ['Machine fingerprint', <code key="fingerprint" className={list.mono}>{grant.fingerprint}</code>],
                  ['Related host events', <Link key="events" to={`/audit?${new URLSearchParams({ grant: grant.id }).toString()}`}>View events for this grant</Link>],
                  ['Related authority changes', <Link key="changes" to={`/audit/changes?${new URLSearchParams({ machine: grant.fingerprint }).toString()}`}>View changes for this machine</Link>],
                  ['Status', grant.status],
                  ['Secrets (names only)', grant.secretNames],
                  ['Program', grant.program],
                  ['Working directory', grant.workingDirectory],
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
    </>
  )
}
