import { useEffect, useRef, useState } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ApiError, api, setSessionSecret } from '../../api/client'
import { keys, useSession, useStatus } from '../../api/queries'
import { Icon } from '../../components/Icon'
import { Button } from '../../components/Button'
import { Logo } from '../../components/Logo'
import { Loading, Notice, ProblemAlert } from '../../components/Feedback'
import { usePageTitle } from '../../lib/usePageTitle'
import { unlock } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'
import styles from './SignInPage.module.css'

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

/** Sign in to Admin or Approvals with an enrolled passkey. */
export function SignInPage() {
  usePageTitle('Sign in')
  const location = useLocation()
  const queryClient = useQueryClient()
  const session = useSession()
  const status = useStatus()
  const startOperation = useStartOperation()
  const [challenge, setChallenge] = useState<Challenge | null>(null)
  const [error, setError] = useState<unknown>(null)
  const passkeyAbort = useRef<AbortController | null>(null)
  // Cancel is offered only while the browser's passkey prompt is open: before that there is nothing to cancel.
  const [prompting, setPrompting] = useState(false)
  // A cancelled prompt is not a failure: the page is simply ready again, with a short note.
  const [cancelled, setCancelled] = useState(false)
  const start = useMutation({ mutationFn: () => api.post('/api/v1/session/inline', { body: {} }), onSuccess: (reply) => { setChallenge(reply.proof); setError(null) } })

  async function signIn() {
    if (!challenge || challenge.mode !== 'webauthn') return
    const controller = new AbortController()
    passkeyAbort.current = controller
    setPrompting(true)
    setCancelled(false)
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
      if (reason instanceof DOMException && (reason.name === 'AbortError' || reason.name === 'NotAllowedError')) {
        // Ready again at once: a fresh sign-in is prepared, so the next click opens the prompt.
        setCancelled(true)
        start.mutate()
      } else {
        setError(reason)
      }
    } finally {
      if (passkeyAbort.current === controller) passkeyAbort.current = null
      setPrompting(false)
    }
  }

  function cancelSignIn() {
    passkeyAbort.current?.abort()
  }

  const login = session.data?.login

  // Until the status is known and the sign-in is being prepared, the button is disabled and not named "Sign in with passkey", so a click on that name always opens the passkey prompt.
  // The challenge is asked for as the page opens (asking is not a passkey prompt), so signing in is one click. After a failure the person starts again with the button.
  const autoStarted = useRef(false)
  // Not while the status is being read again: after a lock the cached status still says unlocked.
  const unlocked = status.data !== undefined && !status.data.remote && !status.data.locked && !status.isFetching
  const locked = status.data?.locked === true
  // A lock seen after an early start (the status was stale): forget it, so that the unlock starts the sign-in again.
  useEffect(() => {
    if (!locked) return
    autoStarted.current = false
    start.reset()
  }, [locked]) // eslint-disable-line react-hooks/exhaustive-deps -- reset only when the lock is seen
  useEffect(() => {
    if (!unlocked || autoStarted.current || login?.state === 'waiting') return
    autoStarted.current = true
    start.mutate()
  }, [unlocked]) // eslint-disable-line react-hooks/exhaustive-deps -- once, when the authority is known to be unlocked

  if (session.data?.authenticated) return <Navigate to={location.state?.returnTo ?? '/'} replace />

  if (status.data?.remote) {
    return (
      <div className={styles.page}>
        <div className={styles.brand}>
          <h1 className={styles.name}><Logo className={styles.logo} /></h1>
        </div>
        <p>Open the administration app on the authority to manage access and secrets.</p>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <div className={styles.brand}>
        <h1 className={styles.name}><Logo className={styles.logo} /></h1>
      </div>
      <div className={styles.alerts}>
        {status.isPending ? <Loading what="status" /> : null}
        {status.isError ? <ProblemAlert error={status.error} title="The service status could not be read" /> : null}
        {status.data?.locked ? (
          <Notice kind="warning" title="The authority is locked">
            <p><Button variant="primary" onClick={() => startOperation(unlock(true))}><Icon name="unlock" /> Unlock and sign in</Button></p>
          </Notice>
        ) : null}
        {start.isError ? <ProblemAlert error={start.error} title="Sign-in could not be prepared" /> : null}
        {login?.state === 'failed' ? <ProblemAlert error={new ApiError(0, 'sign-in-failed', 'The sign-in did not complete', login.problem ?? 'The passkey tap was not accepted.')} /> : null}
        {error ? <ProblemAlert error={error} title="The sign-in did not complete" /> : null}
        {cancelled && !error ? <p role="status" className={styles.note}>Sign-in cancelled.</p> : null}
      </div>
      {!locked ? <div className={styles.actions}>
        {challenge ? (
          <>
            <Button variant="primary" onClick={() => void signIn()} disabled={prompting}><Icon name="key" /> Sign in with passkey</Button>
            {prompting ? <Button variant="quiet" onClick={cancelSignIn}>Cancel</Button> : null}
          </>
        ) : (
          <Button variant="primary" onClick={() => start.mutate()} disabled={start.isPending || status.isPending}>
            <Icon name="key" /> {start.isPending || status.isPending ? 'Preparing...' : login?.state === 'waiting' || login?.state === 'failed' || error ? 'Try again' : 'Sign in with passkey'}
          </Button>
        )}
      </div> : null}
    </div>
  )
}
