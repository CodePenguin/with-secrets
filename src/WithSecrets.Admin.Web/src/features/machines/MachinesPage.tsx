import { useEffect, useRef, useState } from 'react'
import { useInvitations, useMachines, useSession } from '../../api/queries'
import type { Invitation, Machine } from '../../api/types'
import { Badge, Empty, Facts, PageHeader } from '../../components/Card'
import { DetailsButton, DetailsTable } from '../../components/DetailsTable'
import { Dialog } from '../../components/Dialog'
import { Icon } from '../../components/Icon'
import { Button } from '../../components/Button'
import { Loading, Notice, ProblemAlert, useAnnounce } from '../../components/Feedback'
import { Time } from '../../lib/format'
import { usePageTitle } from '../../lib/usePageTitle'
import { approveHostChange, approveMachine, createPairingInvitation, disableMachine, enableMachine, renameMachine, revokePairingInvitation, trustMachine, untrustMachine, type OperationDef } from '../authorization/operations'
import { usePollInterval } from '../authorization/poll'
import { useStartOperation } from '../authorization/OperationProvider'
import styles from './MachinesPage.module.css'

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

function invitationTone(status: Invitation['status']): 'ok' | 'warn' | 'bad' | 'neutral' {
  return status === 'pending' ? 'warn' : status === 'consumed' ? 'ok' : 'neutral'
}

type Start = (def: OperationDef) => void

function MachineStatus({ machine }: { machine: Machine }) {
  return (
    <div className={styles.badges}>
      <Badge tone={tone(machine.status)}>{machine.status}</Badge>
      {machine.pendingHostName ? <Badge tone="warn">New host name reported</Badge> : null}
      {machine.copyWarning ? <Badge tone="warn">Identity warning</Badge> : null}
    </div>
  )
}

function MachineDetails({ machine, start, onClose, canChange }: { machine: Machine; start: Start; onClose: () => void; canChange: boolean }) {
  const name = machine.friendlyName ?? machine.hostName
  const [copied, setCopied] = useState<'no' | 'yes' | 'failed'>('no')

  async function copyFingerprint() {
    try {
      await navigator.clipboard.writeText(machine.fingerprint)
      setCopied('yes')
    } catch {
      setCopied('failed')
    }
  }

  return (
    <Dialog title={name} onCancel={onClose} footer={
      <>
        <Button onClick={onClose}>Close</Button>
        {canChange && machine.actions.map(action => (
          <Button key={action} variant={action === 'approve' ? 'primary' : action === 'disable' || action === 'untrust' ? 'dangerOutline' : 'secondary'}
            onClick={() => start(builders[action](machine))}>
            {actionLabels[action]}{' '}<span className="visually-hidden">{name}</span>
          </Button>
        ))}
      </>
    }>
      {machine.copyWarning ? (
        <Notice kind="warning" title="This machine's identity may have been copied">
          <p>
            Its connection was replaced by a connection from a different address {machine.copyWarning.count} times within 10 minutes (from {machine.copyWarning.firstAddress} and {machine.copyWarning.lastAddress}). Two programs may be using this
            machine's key. Disable this machine if you did not start both.
          </p>
        </Notice>
      ) : null}
      <Facts items={[
        ['Status', <MachineStatus key="state" machine={machine} />],
        ['Host name', machine.hostName],
        ...(machine.pendingHostName ? ([['Reported host name', machine.pendingHostName]] as const) : []),
        ['Enrolled', <Time key="c" value={machine.created} />],
        ['Updated', <Time key="u" value={machine.updated} />],
      ]} />
      <div className={styles.fingerprint}>
        <strong>Fingerprint</strong>
        <code className={styles.mono}>{machine.display}</code>
        <details>
          <summary>Show full fingerprint</summary>
          <code className={styles.mono}>{machine.fingerprint}</code>
        </details>
        <Button variant="secondary" onClick={() => void copyFingerprint()}>
          Copy full fingerprint{' '}<span className="visually-hidden">for {name}</span>
        </Button>
        <span role="status" className={styles.copyStatus}>
          {copied === 'yes' ? 'Copied.' : copied === 'failed' ? 'Copying was not possible here. Select the fingerprint and copy it.' : ''}
        </span>
      </div>
    </Dialog>
  )
}

function MachineTable({ machines, label, onOpen }: { machines: readonly Machine[]; label: string; onOpen: (fingerprint: string) => void }) {
  return (
    <DetailsTable label={label} columns={['Machine', 'Status', 'Fingerprint']}>
      {machines.map(machine => {
        const prefix = machine.display.split(' ', 4).join(' ')
        return (
          <tr key={machine.fingerprint}>
            <th scope="row">
              <DetailsButton title={machine.friendlyName ?? machine.hostName} subtitle={machine.thisMachine ? 'This machine' : undefined}
                description={'View machine ' + machine.display} onClick={() => onOpen(machine.fingerprint)} />
            </th>
            <td><MachineStatus machine={machine} /></td>
            <td><code className={styles.mono}>{prefix}{prefix.length < machine.display.length ? '…' : ''}</code></td>
          </tr>
        )
      })}
    </DetailsTable>
  )
}

function InvitationDetails({ invitation, canChange, onClose, start }: { invitation: Invitation; canChange: boolean; onClose: () => void; start: Start }) {
  return (
    <Dialog title="Pairing invitation" onCancel={onClose} footer={
      <>
        <Button onClick={onClose}>Close</Button>
        {canChange && invitation.canRevoke ? (
          <Button variant="dangerOutline" onClick={() => start(revokePairingInvitation(invitation))}>Revoke invitation</Button>
        ) : null}
      </>
    }>
      <Facts items={[
        ['Invitation ID', <code key="id" className={styles.mono}>{invitation.id}</code>],
        ['Status', <Badge key="status" tone={invitationTone(invitation.status)}>{invitation.status}</Badge>],
        ['Created', <Time key="c" value={invitation.created} />],
        ['Expires', <Time key="e" value={invitation.expires} />],
        ...(invitation.ended ? ([['Ended', <Time key="n" value={invitation.ended} />]] as const) : []),
        ...(invitation.machine ? ([['Machine', <code key="m" className={styles.mono}>{invitation.machine}</code>]] as const) : []),
      ]} />
    </Dialog>
  )
}

export function MachinesPage() {
  usePageTitle('Machines')
  const pollMs = usePollInterval() * 5
  const machines = useMachines(true, pollMs)
  const invitations = useInvitations(true, pollMs)
  const start = useStartOperation()
  const session = useSession()
  const canChange = session.data?.capabilities.includes('admin.decide') === true
  const announce = useAnnounce()
  const [selection, setSelection] = useState<{ kind: 'machine' | 'invitation'; id: string } | null>(null)
  const selectedMachine = selection?.kind === 'machine' ? machines.data?.find(machine => machine.fingerprint === selection.id) : undefined
  const selectedInvitation = selection?.kind === 'invitation' ? invitations.data?.find(invitation => invitation.id === selection.id) : undefined
  const close = () => setSelection(null)
  const openMachine = (id: string) => setSelection({ kind: 'machine', id })
  const perform = (operation: OperationDef) => {
    close()
    start(operation)
  }
  const waiting = machines.data?.filter((machine) => machine.status === 'pending') ?? []
  const others = machines.data?.filter((machine) => machine.status !== 'pending') ?? []

  // A machine that pairs while this view is open is announced (the row appears under waiting machines; nothing moves focus).
  const known = useRef<Set<string> | null>(null)
  useEffect(() => {
    if (!machines.data) return
    const now = new Set(waiting.map((machine) => machine.fingerprint))
    if (known.current) {
      const fresh = waiting.filter((machine) => !known.current?.has(machine.fingerprint))
      if (fresh.length > 0) announce(`A machine paired: ${fresh.map((machine) => machine.hostName).join(', ')}.` + (canChange ? ' Check its fingerprint and host name, then approve it.' : ''))
    }
    known.current = now
  }, [machines.data, canChange]) // eslint-disable-line react-hooks/exhaustive-deps -- compared against the machines already seen

  return (
    <>
      <PageHeader title="Machines">
        {canChange ? <Button variant="primary" onClick={() => start(createPairingInvitation())}><Icon name="plus" /> Add a machine</Button> : null}
      </PageHeader>

      <section className={styles.section} aria-labelledby="invitations-heading">
        <h2 id="invitations-heading">Invitations</h2>
        {invitations.isPending ? <Loading what="invitations" /> : null}
        {invitations.isError ? (
          <>
            <ProblemAlert error={invitations.error} title="The invitations could not be listed" />
            <p>
              <Button onClick={() => void invitations.refetch()}>
                Try again <span className="visually-hidden">loading invitations</span>
              </Button>
            </p>
          </>
        ) : null}
        {invitations.data?.length === 0 ? <Empty>No invitation has been created.</Empty> : null}
        {invitations.data && invitations.data.length > 0 ? (
          <DetailsTable label="Invitations" columns={['Invitation', 'Status', 'Expires']}>
            {invitations.data.map(invitation => (
              <tr key={invitation.id}>
                <th scope="row">
                  <DetailsButton title={invitation.id} description="View invitation" onClick={() => setSelection({ kind: 'invitation', id: invitation.id })} />
                </th>
                <td><Badge tone={invitationTone(invitation.status)}>{invitation.status}</Badge></td>
                <td><Time value={invitation.expires} /></td>
              </tr>
            ))}
          </DetailsTable>
        ) : null}
      </section>

      {machines.isPending ? <Loading what="machines" /> : null}
      {machines.isError ? (
        <>
          <ProblemAlert error={machines.error} title="The machines could not be listed" />
          <p>
            <Button onClick={() => void machines.refetch()}>
              Try again <span className="visually-hidden">loading machines</span>
            </Button>
          </p>
        </>
      ) : null}
      {waiting.length > 0 ? (
        <section className={styles.section} aria-labelledby="paired-heading">
          <h2 id="paired-heading">{waiting.length === 1 ? 'A machine paired and is waiting for you' : waiting.length + ' machines paired and are waiting for you'}</h2>
          <MachineTable machines={waiting} label="Machines waiting for approval" onOpen={openMachine} />
        </section>
      ) : null}
      {machines.data?.length === 0 ? <Empty>No machine has enrolled yet.</Empty> : null}
      {others.length > 0 ? (
        <section className={styles.section} aria-labelledby="enrolled-heading">
          <h2 id="enrolled-heading">Enrolled machines</h2>
          <MachineTable machines={others} label="Machines" onOpen={openMachine} />
        </section>
      ) : null}

      {selectedMachine ? <MachineDetails key={selectedMachine.fingerprint} machine={selectedMachine} canChange={canChange} onClose={close} start={perform} /> : null}
      {selectedInvitation ? <InvitationDetails invitation={selectedInvitation} canChange={canChange} onClose={close} start={perform} /> : null}
    </>
  )
}
