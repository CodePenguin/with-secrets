import { useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ApiError, api, setSessionSecret } from '../../api/client'
import { keys, useSession, useStatus } from '../../api/queries'
import { Badge, Card, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Loading, Notice, ProblemAlert } from '../../components/Feedback'
import { usePageTitle } from '../../lib/usePageTitle'
import { unlock } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'

type Challenge = { mode: string; payload: string }

function base64url(text: string): Uint8Array<ArrayBuffer> {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4))
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index)
  return bytes
}

function encode(bytes: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Sign-in grants this browser a read-only session. Every state change still needs its own passkey authorization. */
export function SignInPage() {
  usePageTitle('Sign in')
  const queryClient = useQueryClient()
  const session = useSession()
  const status = useStatus()
  const startOperation = useStartOperation()
  const [challenge, setChallenge] = useState<Challenge | null>(null)
  const [error, setError] = useState<unknown>(null)
  const passkeyAbort = useRef<AbortController | null>(null)
  const start = useMutation({ mutationFn: () => api.post('/api/v1/session/inline', { body: {} }), onSuccess: (reply) => { setChallenge(reply.proof); setError(null) } })

  async function signIn() {
    if (!challenge || challenge.mode !== 'webauthn') return
    const controller = new AbortController()
    passkeyAbort.current = controller
    try {
      const payload = JSON.parse(challenge.payload) as { bind: string; rpId: string; timeout: number }
      // This is the first asynchronous operation in this click: user activation is still live here.
      const pendingCredential = navigator.credentials.get({ publicKey: { challenge: base64url(payload.bind), rpId: payload.rpId, timeout: payload.timeout, userVerification: 'required' }, signal: controller.signal })
      const credential = await pendingCredential
      if (credential === null) throw new ApiError(0, 'passkey-cancelled', 'Sign-in cancelled', 'The passkey prompt was cancelled.')
      const assertion = credential as PublicKeyCredential
      const response = assertion.response as AuthenticatorAssertionResponse
      const proof = JSON.stringify({ id: encode(assertion.rawId), authenticatorData: encode(response.authenticatorData), clientDataJSON: encode(response.clientDataJSON), signature: encode(response.signature) })
      await api.post('/api/v1/session/inline/proof', { body: { proof } })
      const claimed = await api.post('/api/v1/session/claim', { body: {} })
      setSessionSecret(claimed.antiForgery)
      setChallenge(null)
      setError(null)
      await queryClient.invalidateQueries({ queryKey: keys.session })
    } catch (reason) {
      await api.delete('/api/v1/session/inline', {}).catch(() => undefined)
      setChallenge(null)
      setError(reason instanceof DOMException && reason.name === 'AbortError' ? new ApiError(0, 'passkey-cancelled', 'Sign-in cancelled', 'The passkey prompt was cancelled.') : reason)
    } finally {
      if (passkeyAbort.current === controller) passkeyAbort.current = null
    }
  }

  function cancelSignIn() {
    if (passkeyAbort.current) {
      passkeyAbort.current.abort()
      return
    }
    void api.delete('/api/v1/session/inline', {}).catch(() => undefined)
    setChallenge(null)
  }

  const login = session.data?.login

  return (
    <>
      <PageHeader title="Sign in" />
      <Card title="The authority">
        {status.isPending ? <Loading what="status" /> : status.isError ? <ProblemAlert error={status.error} title="The service status could not be read" /> : (
          <>
            <Facts items={[["State", status.data.locked ? <Badge tone="warn">Locked</Badge> : <Badge tone="ok">Unlocked</Badge>], ["Unlock mode", status.data.unlockMode]]} />
            {status.data.locked ? <><Notice kind="warning" title="The authority is locked">Secret requests are refused until it is unlocked. Unlocking needs your passkey, not a signed-in session.</Notice><p><Button variant="primary" onClick={() => startOperation(unlock())}>Unlock the authority</Button></p></> : null}
          </>
        )}
      </Card>

      <Card title="Sign in with your passkey">
        <p>Signing in starts a read-only session: you can look, but every change asks for its own passkey tap.</p>
        {start.isError ? <ProblemAlert error={start.error} title="Sign-in could not be prepared" /> : null}
        {login?.state === 'failed' ? <ProblemAlert error={new ApiError(0, 'sign-in-failed', 'The sign-in did not complete', login.problem ?? 'The passkey tap was not accepted.')} /> : null}
        {error ? <ProblemAlert error={error} title="The sign-in did not complete" /> : null}
        {challenge ? (
          <>
            <Notice kind="info" title="Ready to sign in">The service has prepared a passkey challenge for this browser. Continue here to open the browser’s passkey prompt.</Notice>
            <p><Button variant="primary" onClick={() => void signIn()}>Sign in with passkey</Button> <Button onClick={cancelSignIn}>Cancel</Button></p>
          </>
        ) : (
          <Button variant="primary" onClick={() => start.mutate()} disabled={start.isPending}>
            {start.isPending ? 'Preparing sign-in...' : login?.state === 'waiting' || login?.state === 'failed' ? 'Start the sign-in again' : 'Sign in'}
          </Button>
        )}
      </Card>
    </>
  )
}
