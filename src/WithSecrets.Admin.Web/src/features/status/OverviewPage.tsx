import { Link } from 'react-router-dom'
import { useGrants, useMachines, useStatus } from '../../api/queries'
import { Badge, Card, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Loading, Notice, ProblemAlert } from '../../components/Feedback'
import { usePageTitle } from '../../lib/usePageTitle'
import { lock, unlock } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'

export function OverviewPage() {
  usePageTitle('Overview')
  const status = useStatus()
  const machines = useMachines(true)
  const grants = useGrants(true)
  const start = useStartOperation()

  if (status.isPending) return <Loading what="the status" />
  if (status.isError) return <ProblemAlert error={status.error} title="The status could not be read" />
  const s = status.data
  const pending = machines.data?.filter((machine) => machine.status === 'pending').length
  const changed = machines.data?.filter((machine) => machine.pendingHostName).length
  const active = grants.data?.filter((grant) => grant.state === 'active').length
  const mismatch = s.version !== __APP_VERSION__

  return (
    <>
      <PageHeader title="Overview">
        {s.locked ? (
          <Button variant="primary" onClick={() => start(unlock())}>
            Unlock the authority
          </Button>
        ) : (
          <Button variant="danger" onClick={() => start(lock())}>
            Lock the authority
          </Button>
        )}
      </PageHeader>

      {s.locked ? (
        <Notice kind="warning" title="The authority is locked">
          Secret requests are refused until it is unlocked. Everything here can still be read; changes other than the unlock wait until then.
        </Notice>
      ) : null}
      {mismatch ? (
        <Notice kind="warning" title="This page and the service are different versions">
          The page is version {__APP_VERSION__} and the service is version {s.version}. Reload the page; if it stays, the service was not built with this page.
        </Notice>
      ) : null}

      <Card title="Authority">
        <Facts
          items={[
            ['State', s.locked ? <Badge tone="warn">Locked</Badge> : <Badge tone="ok">Unlocked</Badge>],
            ['Unlock mode', s.unlockMode],
            ['Unlocked how', s.unlockedHow ?? 'not unlocked'],
            ['Service version', s.version],
            ['Page version', __APP_VERSION__],
            ['API version', s.apiVersion],
          ]}
        />
      </Card>

      <Card title="Needs your attention">
        <ul>
          <li>
            {pending === undefined ? 'Machines: loading' : pending === 0 ? 'No machine is waiting for approval.' : <Link to="/machines">{pending} machine(s) waiting for approval</Link>}
          </li>
          <li>{changed ? <Link to="/machines">{changed} machine(s) reported a new host name</Link> : 'No machine reported a new host name.'}</li>
          <li>{active === undefined ? 'Grants: loading' : <Link to="/grants">{active} active grant(s)</Link>}</li>
        </ul>
      </Card>
    </>
  )
}
