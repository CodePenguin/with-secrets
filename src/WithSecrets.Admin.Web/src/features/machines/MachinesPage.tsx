import { useMachines } from '../../api/queries'
import type { Machine } from '../../api/types'
import { Badge, Empty, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Loading, ProblemAlert } from '../../components/Feedback'
import list from '../../components/List.module.css'
import { Time } from '../../lib/format'
import { usePageTitle } from '../../lib/usePageTitle'
import { approveHostChange, approveMachine, disableMachine, enableMachine, renameMachine, trustMachine, untrustMachine, type OperationDef } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'

const actionLabels: Record<Machine['actions'][number], string> = {
  approve: 'Approve',
  disable: 'Disable',
  enable: 'Enable',
  untrust: 'Withdraw trust',
  trust: 'Trust again',
  'approve-host-change': 'Accept host name',
  rename: 'Rename',
}

const builders: Record<Machine['actions'][number], (machine: Machine) => OperationDef> = {
  approve: approveMachine,
  disable: disableMachine,
  enable: enableMachine,
  untrust: untrustMachine,
  trust: trustMachine,
  'approve-host-change': approveHostChange,
  rename: renameMachine,
}

function tone(status: Machine['status']): 'ok' | 'warn' | 'bad' | 'neutral' {
  return status === 'trusted' ? 'ok' : status === 'pending' ? 'warn' : status === 'disabled' || status === 'untrusted' ? 'bad' : 'neutral'
}

export function MachinesPage() {
  usePageTitle('Machines')
  const machines = useMachines(true)
  const start = useStartOperation()

  return (
    <>
      <PageHeader title="Machines" />
      <p>Each machine that asks for secrets has its own identity. A machine is only served once you approve it here.</p>
      {machines.isPending ? <Loading what="machines" /> : null}
      {machines.isError ? <ProblemAlert error={machines.error} title="The machines could not be listed" /> : null}
      {machines.data?.length === 0 ? <Empty>No machine has enrolled yet.</Empty> : null}
      {machines.data && machines.data.length > 0 ? (
        <ul className={list.list} aria-label="Machines">
          {machines.data.map((machine) => {
            const name = machine.friendlyName ?? machine.hostName

            return (
              <li key={machine.fingerprint} className={list.item}>
                <div className={list.itemHeader}>
                  <h2>{name}</h2>
                  <Badge tone={tone(machine.status)}>{machine.status}</Badge>
                  {machine.thisMachine ? <Badge tone="neutral">This machine</Badge> : null}
                  {machine.pendingHostName ? <Badge tone="warn">New host name reported</Badge> : null}
                </div>
                <Facts
                  items={[
                    ['Fingerprint', <span key="f" className={list.mono}>{machine.display}</span>],
                    ['Host name', machine.hostName],
                    ...(machine.pendingHostName ? ([['Reported host name', machine.pendingHostName]] as const) : []),
                    ['Revision', String(machine.revision)],
                    ['Enrolled', <Time key="c" value={machine.created} />],
                    ['Updated', <Time key="u" value={machine.updated} />],
                  ]}
                />
                {machine.actions.length > 0 ? (
                  <div className={list.actions}>
                    {machine.actions.map((action) => (
                      <Button key={action} variant={action === 'approve' ? 'primary' : 'secondary'} onClick={() => start(builders[action](machine))}>
                        {actionLabels[action]}
                        <span className="visually-hidden"> {name}</span>
                      </Button>
                    ))}
                  </div>
                ) : null}
              </li>
            )
          })}
        </ul>
      ) : null}
    </>
  )
}
