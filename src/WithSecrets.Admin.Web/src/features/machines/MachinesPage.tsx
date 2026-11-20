import { useEffect, useRef, useState } from 'react'
import { useInvitations, useMachines } from '../../api/queries'
import type { Invitation, Machine } from '../../api/types'
import { Badge, Empty, Facts, PageHeader } from '../../components/Card'
import { Flow } from '../../components/Icon'
import { Button } from '../../components/Button'
import { Loading, Notice, ProblemAlert, useAnnounce } from '../../components/Feedback'
import list from '../../components/List.module.css'
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

/** One machine: its facts once, and what can be done to it. A machine that has just paired (Pending) is shown by the "paired" section above the list, not twice. */
function MachineItem({ machine, start, level }: { machine: Machine; start: Start; level: 'h2' | 'h3' }) {
  const name = machine.friendlyName ?? machine.hostName
  const Heading = level
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
    <li className={[list.item, machine.status === 'pending' ? styles.pairedItem : ''].join(' ')}>
      <div className={list.itemHeader}>
        <Heading>{name}</Heading>
        <Badge tone={tone(machine.status)}>{machine.status}</Badge>
        {machine.thisMachine ? <Badge tone="neutral">This machine</Badge> : null}
        {machine.pendingHostName ? <Badge tone="warn">New host name reported</Badge> : null}
      </div>
      {machine.copyWarning ? (
        <Notice kind="warning" title="This machine's identity may have been copied">
          <p>
            Its connection was replaced by a connection from a different address {machine.copyWarning.count} times within 10 minutes (from {machine.copyWarning.firstAddress} and {machine.copyWarning.lastAddress}). Two programs may be using this
            machine's key. Disable this machine if you did not start both.
          </p>
        </Notice>
      ) : null}
      <Facts
        items={[
          [
            'Fingerprint',
            <div key="f" className={styles.fingerprint}>
              <span className={styles.mono}>{machine.display}</span>
              <details>
                <summary>Show full fingerprint</summary>
                <code className={styles.mono}>{machine.fingerprint}</code>
              </details>
              <Button variant="quiet" onClick={() => void copyFingerprint()}>
                Copy full fingerprint{' '}
                <span className="visually-hidden">for {name}</span>
              </Button>
              <span role="status" className={styles.copyStatus}>
                {copied === 'yes' ? 'Copied.' : copied === 'failed' ? 'Copying was not possible here; select the fingerprint and copy it.' : ''}
              </span>
            </div>,
          ],
          ...(machine.friendlyName ? ([['Host name', machine.hostName]] as const) : []),
          ...(machine.pendingHostName ? ([['Reported host name', machine.pendingHostName]] as const) : []),
          ['Enrolled', <Time key="c" value={machine.created} />],
          ['Updated', <Time key="u" value={machine.updated} />],
        ]}
      />
      {machine.actions.length > 0 ? (
        <div className={list.actions}>
          {machine.actions.map((action) => (
            <Button key={action} variant={action === 'approve' ? 'primary' : action === 'disable' || action === 'untrust' ? 'danger' : 'secondary'} onClick={() => start(builders[action](machine))}>
              {actionLabels[action]}
              <span className="visually-hidden"> {name}</span>
            </Button>
          ))}
        </div>
      ) : null}
    </li>
  )
}

/**
 * Machines, and how a new one gets here: "Add a machine" makes a pairing invitation (its own fresh passkey tap, the bundle shown once), the machine pairs itself with it and appears as a card at the top
 * ("A machine paired", with its fingerprint and host name to check against that machine's own screen, and Approve), the list holds every other machine, and the invitations are listed by status below.
 * The view asks again every few seconds, so a machine that pairs while this page is open appears by itself.
 */
export function MachinesPage() {
  usePageTitle('Machines')
  const pollMs = usePollInterval() * 5
  const machines = useMachines(true, pollMs)
  const invitations = useInvitations(true, pollMs)
  const start = useStartOperation()
  const announce = useAnnounce()
  const waiting = machines.data?.filter((machine) => machine.status === 'pending') ?? []
  const others = machines.data?.filter((machine) => machine.status !== 'pending') ?? []

  // A machine that pairs while this view is open is announced (the card appears at the top; nothing moves focus).
  const known = useRef<Set<string> | null>(null)
  useEffect(() => {
    if (!machines.data) return
    const now = new Set(waiting.map((machine) => machine.fingerprint))
    if (known.current) {
      const fresh = waiting.filter((machine) => !known.current?.has(machine.fingerprint))
      if (fresh.length > 0) announce(`A machine paired: ${fresh.map((machine) => machine.hostName).join(', ')}. Check its fingerprint and host name, then approve it.`)
    }
    known.current = now
  }, [machines.data]) // eslint-disable-line react-hooks/exhaustive-deps -- compared against the machines already seen

  return (
    <>
      <PageHeader title="Machines">
        <Button variant="primary" onClick={() => start(createPairingInvitation())}>
          Add a machine
        </Button>
      </PageHeader>
      <Flow label="How a machine is added" steps={[{ icon: 'plus', text: 'Add a machine' }, { icon: 'link', text: 'It pairs with the invitation' }, { icon: 'check', text: 'You approve it' }]} />
      {machines.isPending ? <Loading what="machines" /> : null}
      {machines.isError ? (
        <>
          <ProblemAlert error={machines.error} title="The machines could not be listed" />
          <p>
            <Button onClick={() => void machines.refetch()}>
              Try again{' '}
              <span className="visually-hidden">loading machines</span>
            </Button>
          </p>
        </>
      ) : null}

      {waiting.length > 0 ? (
        <section className={styles.paired} aria-labelledby="paired-heading">
          <h2 id="paired-heading">{waiting.length === 1 ? 'A machine paired and is waiting for you' : `${waiting.length} machines paired and are waiting for you`}</h2>
          <ul className={list.list} aria-label="Machines waiting for approval">
            {waiting.map((machine) => (
              <MachineItem key={machine.fingerprint} machine={machine} start={start} level="h3" />
            ))}
          </ul>
        </section>
      ) : null}

      {machines.data?.length === 0 ? <Empty>No machine has enrolled yet.</Empty> : null}
      {others.length > 0 ? (
        <ul className={list.list} aria-label="Machines">
          {others.map((machine) => (
            <MachineItem key={machine.fingerprint} machine={machine} start={start} level="h2" />
          ))}
        </ul>
      ) : null}

      <section className={styles.section} aria-labelledby="invitations-heading">
        <h2 id="invitations-heading">Invitations</h2>
        <p>
          Each invitation works once and lasts 10 minutes.
        </p>
        {invitations.isError ? (
          <>
            <ProblemAlert error={invitations.error} title="The invitations could not be listed" />
            <p>
              <Button onClick={() => void invitations.refetch()}>
                Try again{' '}
                <span className="visually-hidden">loading invitations</span>
              </Button>
            </p>
          </>
        ) : null}
        {invitations.data?.length === 0 ? <Empty>No invitation has been created.</Empty> : null}
        {invitations.data && invitations.data.length > 0 ? (
          <ul className={[list.list, list.compact].join(' ')} aria-label="Invitations">
            {invitations.data.map((invitation) => (
              <li key={invitation.id} className={list.item}>
                <div className={list.itemHeader}>
                  <h3 className={styles.mono}>{invitation.id}</h3>
                  <Badge tone={invitationTone(invitation.status)}>{invitation.status}</Badge>
                </div>
                <Facts
                  items={[
                    ['Created', <Time key="c" value={invitation.created} />],
                    ['Expires', <Time key="e" value={invitation.expires} />],
                    ...(invitation.ended ? ([['Ended', <Time key="n" value={invitation.ended} />]] as const) : []),
                    ...(invitation.machine ? ([['Machine', <span key="m" className={styles.mono}>{invitation.machine}</span>]] as const) : []),
                  ]}
                />
                {invitation.canRevoke ? (
                  <div className={list.actions}>
                    <Button variant="danger" onClick={() => start(revokePairingInvitation(invitation))}>
                      Revoke
                      <span className="visually-hidden"> invitation {invitation.id}</span>
                    </Button>
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}
      </section>
    </>
  )
}
