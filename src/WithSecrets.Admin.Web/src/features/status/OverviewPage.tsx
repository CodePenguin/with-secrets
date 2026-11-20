import { Link } from 'react-router-dom'
import { useApprovals, useGrants, useMachines, useStatus } from '../../api/queries'
import { Card, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Icon } from '../../components/Icon'
import { Loading, Notice, ProblemAlert } from '../../components/Feedback'
import { usePageTitle } from '../../lib/usePageTitle'
import { lock, unlock } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'

export function OverviewPage() {
  usePageTitle('Overview')
  const status = useStatus()
  const machines = useMachines(true)
  const grants = useGrants(true)
  const approvals = useApprovals(true)
  const start = useStartOperation()

  if (status.isPending) return <Loading what="the status" />
  if (status.isError) return <ProblemAlert error={status.error} title="The status could not be read" />
  const s = status.data
  const pending = machines.data?.filter((machine) => machine.status === 'pending').length
  const changed = machines.data?.filter((machine) => machine.pendingHostName).length
  const active = grants.data?.filter((grant) => grant.state === 'active').length
  const waiting = approvals.data?.items.length
  const mismatch = s.version !== __APP_VERSION__

  return (
    <>
      <PageHeader title="Overview">
        {s.locked ? (
          <Button variant="primary" onClick={() => start(unlock())}>
            <Icon name="unlock" /> Unlock the authority
          </Button>
        ) : (
          <Button variant="danger" onClick={() => start(lock())}>
            <Icon name="lock" /> Lock the authority
          </Button>
        )}
      </PageHeader>

      {s.locked ? (
        <Notice kind="warning" title="The authority is locked">
          Secret requests are refused until it is unlocked.
        </Notice>
      ) : null}
      {mismatch ? (
        <Notice kind="warning" title="This page and the service are different versions">
          This page is version {__APP_VERSION__} and the service is version {s.version}. Reload the page; if this stays, the service needs updating.
        </Notice>
      ) : null}

      <Card title="Authority">
        <Facts
          items={[
            ['Unlock mode', s.unlockMode],
            ['Version', s.version],
          ]}
        />
      </Card>

      <Card title="Needs your attention">
        {machines.isError ? (
          <>
            <ProblemAlert error={machines.error} title="Machine attention could not be loaded" />
            <p>
              <Button onClick={() => void machines.refetch()}>
                Try again{' '}
                <span className="visually-hidden">loading machine attention</span>
              </Button>
            </p>
          </>
        ) : null}
        {machines.data && (waiting || pending || changed) ? (
          <ul>
            {waiting ? (
              <li>
                <Link to="/access">{waiting === 1 ? '1 run request is waiting' : waiting + ' run requests are waiting'}</Link>
              </li>
            ) : null}
            {pending ? (
              <li>
                <Link to="/machines">{pending === 1 ? '1 machine is waiting for approval' : pending + ' machines are waiting for approval'}</Link>
              </li>
            ) : null}
            {changed ? (
              <li>
                <Link to="/machines">{changed === 1 ? '1 machine reported a new host name' : changed + ' machines reported a new host name'}</Link>
              </li>
            ) : null}
          </ul>
        ) : machines.data ? (
          <p>Nothing needs your attention.</p>
        ) : machines.isPending ? (
          <Loading what="machine attention" />
        ) : null}
      </Card>

      <Card title="At a glance">
        {grants.isError ? (
          <>
            <ProblemAlert error={grants.error} title="Active grants could not be loaded" />
            <p>
              <Button onClick={() => void grants.refetch()}>
                Try again{' '}
                <span className="visually-hidden">loading active grants</span>
              </Button>
            </p>
          </>
        ) : null}
        {grants.data ? (
          active === 0 ? (
            <p>No active grants.</p>
          ) : (
            <p>
              <Link to="/access">{active} active {active === 1 ? 'grant' : 'grants'}</Link>
            </p>
          )
        ) : grants.isPending ? (
          <Loading what="active grants" />
        ) : null}
      </Card>
    </>
  )
}
