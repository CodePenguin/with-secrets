import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ApiError, api } from '../../api/client'
import { keys, useSession, useStatus } from '../../api/queries'
import { Badge, Card, Facts, PageHeader } from '../../components/Card'
import { Button, ButtonLink } from '../../components/Button'
import { Loading, Notice, ProblemAlert } from '../../components/Feedback'
import { usePageTitle } from '../../lib/usePageTitle'
import { safeLink } from '../authorization/OperationDialog'
import { unlock } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'

/**
 * Not signed in. A sign-in is one passkey tap on the service's own page (user verification) and gives a read-only session: the session
 * can look at everything and change nothing. The unlock of a locked authority needs no session, only its own authorization.
 */
export function SignInPage() {
  usePageTitle('Sign in')
  const queryClient = useQueryClient()
  const session = useSession()
  const status = useStatus()
  const startOperation = useStartOperation()
  const [link, setLink] = useState<string | null>(null)

  const start = useMutation({
    mutationFn: () => api.post('/api/v1/session', { body: {} }),
    onSuccess: (started) => {
      setLink(safeLink(started.link))
      void queryClient.invalidateQueries({ queryKey: keys.session })
    },
  })

  const login = session.data?.login
  const waiting = login?.state === 'waiting' && link !== null

  return (
    <>
      <PageHeader title="Sign in" />
      <Card title="The authority">
        {status.isPending ? (
          <Loading what="status" />
        ) : status.isError ? (
          <ProblemAlert error={status.error} title="The service status could not be read" />
        ) : (
          <>
            <Facts
              items={[
                ['State', status.data.locked ? <Badge tone="warn">Locked</Badge> : <Badge tone="ok">Unlocked</Badge>],
                ['Unlock mode', status.data.unlockMode],
              ]}
            />
            {status.data.locked ? (
              <>
                <Notice kind="warning" title="The authority is locked">
                  Secret requests are refused until it is unlocked. Unlocking needs your passkey, not a signed-in session.
                </Notice>
                <p>
                  <Button variant="primary" onClick={() => startOperation(unlock())}>
                    Unlock the authority
                  </Button>
                </p>
              </>
            ) : null}
          </>
        )}
      </Card>

      <Card title="Sign in with your passkey">
        <p>Signing in starts a read-only session: you can look, but every change asks for its own passkey tap.</p>
        {start.isError ? <ProblemAlert error={start.error} title="Sign-in could not be started" /> : null}
        {login?.state === 'failed' ? <ProblemAlert error={new ApiError(0, 'sign-in-failed', 'The sign-in did not complete', login.problem ?? 'The passkey tap was not accepted.')} /> : null}
        {waiting ? (
          <>
            <Notice kind="info" title="Waiting for your passkey tap">
              Open the passkey page, check that it says it starts an administrator session, and tap your passkey there. This page carries on by itself afterwards. It waits for as long as you need.
            </Notice>
            <p>
              <ButtonLink href={link} target="_blank" rel="noopener noreferrer" variant="primary" autoFocus>
                Open the passkey page (new tab)
              </ButtonLink>
            </p>
          </>
        ) : (
          <Button variant="primary" onClick={() => start.mutate()} disabled={start.isPending}>
            {start.isPending ? 'Starting...' : login?.state === 'waiting' || login?.state === 'failed' ? 'Start the sign-in again' : 'Sign in'}
          </Button>
        )}
      </Card>
    </>
  )
}
