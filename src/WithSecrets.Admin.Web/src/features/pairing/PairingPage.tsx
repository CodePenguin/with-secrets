import { useInvitations } from '../../api/queries'
import type { Invitation } from '../../api/types'
import { Badge, Empty, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Loading, ProblemAlert } from '../../components/Feedback'
import list from '../../components/List.module.css'
import { Time } from '../../lib/format'
import { usePageTitle } from '../../lib/usePageTitle'
import { createPairingInvitation, revokePairingInvitation } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'

function tone(status: Invitation['status']): 'ok' | 'warn' | 'bad' | 'neutral' {
  return status === 'pending' ? 'warn' : status === 'consumed' ? 'ok' : 'neutral'
}

export function PairingPage() {
  usePageTitle('Pairing')
  const invitations = useInvitations(true)
  const start = useStartOperation()

  return (
    <>
      <PageHeader title="Pairing">
        <Button variant="primary" onClick={() => start(createPairingInvitation())}>
          Create an invitation
        </Button>
      </PageHeader>
      <p>
        An invitation lets one new machine ask to be added to this authority. It is valid for 10 minutes and works once. After the machine pairs it is Pending, and you approve it under Machines after checking its fingerprint and host name. The invitation itself is shown only when you create it; this list shows
        status only.
      </p>
      {invitations.isPending ? <Loading what="invitations" /> : null}
      {invitations.isError ? <ProblemAlert error={invitations.error} title="The invitations could not be listed" /> : null}
      {invitations.data?.length === 0 ? <Empty>No invitation has been created.</Empty> : null}
      {invitations.data && invitations.data.length > 0 ? (
        <ul className={list.list} aria-label="Invitations">
          {invitations.data.map((invitation) => (
            <li key={invitation.id} className={list.item}>
              <div className={list.itemHeader}>
                <h2 className={list.mono}>{invitation.id}</h2>
                <Badge tone={tone(invitation.status)}>{invitation.status}</Badge>
              </div>
              <Facts
                items={[
                  ['Created', <Time key="c" value={invitation.created} />],
                  ['Expires', <Time key="e" value={invitation.expires} />],
                  ...(invitation.ended ? ([['Ended', <Time key="n" value={invitation.ended} />]] as const) : []),
                  ...(invitation.machine ? ([['Machine', <span key="m" className={list.mono}>{invitation.machine}</span>]] as const) : []),
                ]}
              />
              {invitation.canRevoke ? (
                <div className={list.actions}>
                  <Button onClick={() => start(revokePairingInvitation(invitation))}>
                    Revoke
                    <span className="visually-hidden"> invitation {invitation.id}</span>
                  </Button>
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </>
  )
}
