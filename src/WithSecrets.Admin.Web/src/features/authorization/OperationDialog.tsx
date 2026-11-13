import { useEffect, useId, useReducer, useRef, useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError, api, setPendingAuthorization, type PendingAuthorization } from '../../api/client'
import type { Authorization, AuthorizationResult } from '../../api/types'
import { Button, ButtonLink } from '../../components/Button'
import { Dialog } from '../../components/Dialog'
import { Field, checkClass, controlClass } from '../../components/Field'
import { Facts } from '../../components/Card'
import { Notice, ProblemAlert, useAnnounce } from '../../components/Feedback'
import { BundleOnce } from '../pairing/BundleOnce'
import { usePollInterval } from './poll'
import type { FormValues, OperationDef, Prepared } from './operations'
import styles from './OperationDialog.module.css'

/** What a waiting dialog knows of its authorization: after a reload only the id (the rest is read from the service). */
type Waiting = { id: string; operation: string; summary: string; link: string | null; parameters: ReadonlyArray<{ name: string; value: string }> | null; proof: { mode: string; payload: string } | null }

type State =
  | { phase: 'form'; errors: Record<string, string> }
  | { phase: 'review' }
  | { phase: 'asking'; prepared: Prepared }
  | { phase: 'waiting'; waiting: Waiting; prepared: Prepared | null }
  | { phase: 'done'; summary: string; result: AuthorizationResult }
  | { phase: 'failed'; error: unknown; prepared: Prepared | null }

type Action =
  | { type: 'invalid'; errors: Record<string, string> }
  | { type: 'asking'; prepared: Prepared }
  | { type: 'created'; waiting: Waiting }
  | { type: 'challenge'; proof: { mode: string; payload: string }; parameters: ReadonlyArray<{ name: string; value: string }> }
  | { type: 'done'; summary: string; result: AuthorizationResult }
  | { type: 'failed'; error: unknown }
  | { type: 'again'; hasFields: boolean }

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'invalid':
      return { phase: 'form', errors: action.errors }
    case 'asking':
      return { phase: 'asking', prepared: action.prepared }
    case 'created':
      return { phase: 'waiting', waiting: action.waiting, prepared: state.phase === 'asking' ? state.prepared : null }
    case 'challenge':
      return state.phase === 'waiting' && state.waiting.proof === null ? { ...state, waiting: { ...state.waiting, proof: action.proof, parameters: action.parameters } } : state
    case 'done':
      return { phase: 'done', summary: action.summary, result: action.result }
    case 'failed':
      return { phase: 'failed', error: action.error, prepared: 'prepared' in state ? state.prepared : null }
    case 'again':
      return action.hasFields ? { phase: 'form', errors: {} } : { phase: 'review' }
  }
}

/** Only an http(s) link on this machine is ever offered as the passkey page. */
export function safeLink(link: string | null | undefined): string | null {
  if (!link) return null
  try {
    const url = new URL(link)
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)

    return url.protocol === 'http:' && loopback ? url.toString() : null
  } catch {
    return null
  }
}

/**
 * The service answers with the authorization it made: its operation must be the one that was asked. Its parameters are what the passkey signs (the service may add what it derived, for
 * example the full fingerprint or the host name), so they are shown to the person, not compared: the service itself only ever applies the plan it made for what was authorized.
 */
function sameOperation(requested: Prepared, got: Authorization): boolean {
  return got.operation === requested.operation
}

/** Best effort: an authorization that this page no longer waits for is cancelled, so a tap on its page afterwards changes nothing. */
function cancelAuthorization(id: string): void {
  void api.delete('/api/v1/authorizations/{id}', { path: { id } }).catch(() => undefined)
}

const nothing: AuthorizationResult = { outcome: 'applied', code: null, detail: null, link: null, invitation: null, invitationGone: false }

type Props = { def?: OperationDef; resume?: PendingAuthorization; onClose: () => void }

/**
 * One administrative change from start to finish in one modal dialog. First the SPA asks the service to prepare a one-use challenge bound to the reviewed operation. The final confirmation button directly invokes WebAuthn, then submits the assertion. The service verifies it and applies its retained operation; the SPA displays the service's result. Reloading can recover the pending authorization by id.
 */
export function OperationDialog({ def, resume, onClose }: Props) {
  const queryClient = useQueryClient()
  const announce = useAnnounce()
  const pollMs = usePollInterval()
  const formId = useId()
  const hasFields = (def?.fields?.length ?? 0) > 0
  const initial: State = resume
    ? { phase: 'waiting', waiting: { id: resume.id, operation: resume.operation, summary: resume.summary, link: null, parameters: null, proof: null }, prepared: null }
    : hasFields
      ? { phase: 'form', errors: {} }
      : { phase: 'review' }
  const [state, dispatch] = useReducer(reducer, initial)
  const [draft, setDraft] = useState<FormValues>(def?.initial ?? {})
  const mounted = useRef(true)
  const passkeyAbort = useRef<AbortController | null>(null)

  useEffect(() => {
    mounted.current = true

    return () => {
      mounted.current = false
    }
  }, [])

  const waiting = state.phase === 'waiting' ? state.waiting : null
  const waitingId = waiting?.id
  const waitingOperation = waiting?.operation
  const waitingSummary = waiting?.summary ?? ''
  const title = def?.title ?? resume?.title ?? ''

  // Wait for the tap: ask where the authorization stands, and what came of it, until it is settled (no time limit of this page's own).
  useEffect(() => {
    if (!waitingId) return
    let live = true
    let timer: ReturnType<typeof setTimeout> | undefined
    const settle = (action: Action) => {
      if (!live) return
      setPendingAuthorization(null)
      dispatch(action)
      void queryClient.invalidateQueries()
    }
    const outcomeUnknown = async () => {
      // A lock ends every session and every authorization, so the answer to "what became of it" is the authority's state.
      if (waitingOperation === 'lock') {
        try {
          if ((await api.get('/api/v1/status')).locked) {
            settle({ type: 'done', summary: 'The authority is locked.', result: nothing })

            return
          }
        } catch {
          // Fall through to the general sentence.
        }
      }
      settle({
        type: 'failed',
        error: new ApiError(
          0,
          'outcome-unknown',
          'What became of the request cannot be read',
          'Your session ended, or the service no longer holds this request. If you tapped your passkey, the change was made: sign in and look at the audit history (changes). If you did not tap, nothing was changed.',
        ),
      })
    }
    const look = async () => {
      try {
        const current = await api.get('/api/v1/authorizations/{id}', { path: { id: waitingId }, query: { collect: 'invitation' } })
        if (!live) return
        if (current.state === 'consumed' && current.result) {
          const result = current.result
          if (result.outcome === 'failed') {
            settle({ type: 'failed', error: new ApiError(0, result.code ?? 'operation-failed', 'The change was not made', result.detail ?? 'The tap was verified but the change could not be made. Nothing was changed.') })
          } else {
            settle({ type: 'done', summary: waitingSummary, result })
          }
        } else if (current.state === 'pending' && current.proof) {
          dispatch({ type: 'challenge', proof: current.proof, parameters: current.parameters })
          timer = setTimeout(() => void look(), pollMs)
        } else if (current.state === 'pending' || current.state === 'verified' || current.state === 'consumed') {
          timer = setTimeout(() => void look(), pollMs)
        } else {
          const why = current.detail ?? (current.state === 'expired' ? 'The authorization ran out before it was used.' : 'The authorization was ' + current.state + '.')
          settle({ type: 'failed', error: new ApiError(0, 'authorization-' + current.state, 'Authorization ' + current.state, why) })
        }
      } catch (error) {
        if (!live) return
        if (error instanceof ApiError && error.status === 0) {
          timer = setTimeout(() => void look(), pollMs * 3)
        } else if (error instanceof ApiError && (error.status === 401 || error.status === 404)) {
          void outcomeUnknown()
        } else {
          settle({ type: 'failed', error })
        }
      }
    }
    timer = setTimeout(() => void look(), pollMs)

    return () => {
      live = false
      if (timer) clearTimeout(timer)
    }
  }, [waitingId]) // eslint-disable-line react-hooks/exhaustive-deps -- the waiting authorization is read only when its id changes

  useEffect(() => {
    const message: Partial<Record<State['phase'], string>> = {
      asking: 'Asking the service for an authorization.',
      waiting: 'Waiting for your passkey tap.',
      done: 'Done. ' + (state.phase === 'done' ? state.summary : ''),
      failed: 'The change was not made.',
    }
    const text = message[state.phase]
    if (text) announce(text)
  }, [state.phase]) // eslint-disable-line react-hooks/exhaustive-deps -- announced once per phase

  /** Prepare the service-owned, operation-bound challenge. No operation is applied yet. */
  async function continueToPasskey(prepared: Prepared) {
    dispatch({ type: 'asking', prepared })
    try {
      const made = await api.post('/api/v1/authorizations/inline', { body: { operation: prepared.operation, parameters: prepared.parameters } })
      if (!mounted.current) {
        // The dialog was closed while the service was answering: nothing is left waiting for it.
        cancelAuthorization(made.id)

        return
      }
      if (!sameOperation(prepared, made)) {
        cancelAuthorization(made.id)
        dispatch({ type: 'failed', error: new ApiError(0, 'authorization-mismatch', 'Not the same operation', 'The service answered with an authorization for something other than what was asked. Nothing was done.') })

        return
      }
      if (!made.proof || made.proof.mode !== 'webauthn') {
        cancelAuthorization(made.id)
        dispatch({ type: 'failed', error: new ApiError(0, 'proof-unavailable', 'Passkey unavailable', 'The service did not prepare a usable passkey challenge. Nothing was changed.') })
        return
      }
      setPendingAuthorization({ id: made.id, operation: made.operation, title, summary: prepared.summary })
      dispatch({ type: 'created', waiting: { id: made.id, operation: made.operation, summary: prepared.summary, link: null, parameters: made.parameters, proof: made.proof } })
    } catch (error) {
      if (mounted.current) dispatch({ type: 'failed', error })
    }
  }

  /** The click itself synchronously calls WebAuthn before any network request or await. */
  async function confirmInline(waiting: Waiting) {
    if (!waiting.proof) return
    const controller = new AbortController()
    passkeyAbort.current = controller
    try {
      const payload = JSON.parse(waiting.proof.payload) as { bind: string; rpId: string; timeout: number }
      const decode = (text: string) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - text.length % 4) % 4)), (char) => char.charCodeAt(0))
      const challenge = decode(payload.bind)
      const credentialPromise = navigator.credentials.get({ publicKey: { challenge, rpId: payload.rpId, timeout: payload.timeout, userVerification: 'required' }, signal: controller.signal })
      const credential = await credentialPromise
      if (credential === null) throw new ApiError(0, 'passkey-cancelled', 'Passkey not completed', 'The passkey prompt was cancelled. Nothing was changed.')
      const assertion = credential as PublicKeyCredential
      const response = assertion.response as AuthenticatorAssertionResponse
      const encode = (bytes: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
      const proof = JSON.stringify({ id: encode(assertion.rawId), authenticatorData: encode(response.authenticatorData), clientDataJSON: encode(response.clientDataJSON), signature: encode(response.signature) })
      await api.post('/api/v1/authorizations/{id}/proof', { path: { id: waiting.id }, body: { proof } })
    } catch (error) {
      cancelAuthorization(waiting.id)
      setPendingAuthorization(null)
      dispatch({ type: 'failed', error: error instanceof DOMException && error.name === 'AbortError' ? new ApiError(0, 'passkey-cancelled', 'Passkey not completed', 'The passkey prompt was cancelled. Nothing was changed.') : error })
    } finally {
      if (passkeyAbort.current === controller) passkeyAbort.current = null
    }
  }

  function cancelWaiting() {
    if (passkeyAbort.current) passkeyAbort.current.abort()
    else close()
  }

  function close() {
    if (state.phase === 'waiting') {
      // Cancelling a waiting request cancels it at the service too: a tap on its page afterwards changes nothing.
      cancelAuthorization(state.waiting.id)
    }
    setPendingAuthorization(null)
    onClose()
  }

  function submitForm(event: FormEvent) {
    event.preventDefault()
    if (!def || state.phase !== 'form') return
    const result = def.prepare(draft)
    if ('errors' in result) dispatch({ type: 'invalid', errors: result.errors })
    else void continueToPasskey(result)
  }

  const confirmVariant = def?.danger ? 'danger' : 'primary'

  let body
  let footer
  if (state.phase === 'form' && def) {
    body = (
      <form id={formId} onSubmit={submitForm} noValidate className={styles.form}>
        {def.intro ? <p>{def.intro}</p> : null}
        {def.about ? <Facts items={def.about} /> : null}
        {def.warning ? <Notice kind="warning">{def.warning}</Notice> : null}
        {def.fields?.map((field, index) => (
          <Field key={field.name} label={field.label} hint={field.hint} error={state.errors[field.name]} required={field.required}>
            {(control) =>
              field.kind === 'checkbox' ? (
                <input {...control} type="checkbox" className={checkClass} checked={draft[field.name] === true} onChange={(event) => setDraft({ ...draft, [field.name]: event.target.checked })} />
              ) : (
                <input
                  {...control}
                  className={controlClass}
                  type="text"
                  inputMode={field.kind === 'number' ? 'numeric' : undefined}
                  maxLength={field.maxLength}
                  autoComplete="off"
                  spellCheck={false}
                  // eslint-disable-next-line jsx-a11y/no-autofocus -- the first field of a modal form
                  autoFocus={index === 0}
                  value={String(draft[field.name] ?? '')}
                  onChange={(event) => setDraft({ ...draft, [field.name]: event.target.value })}
                />
              )
            }
          </Field>
        ))}
        <p className={styles.hint}>Prepare the passkey confirmation. You will review this operation again before the passkey prompt. Nothing changes until the service verifies your assertion.</p>
      </form>
    )
    footer = (
      <>
        <Button key="cancel" onClick={close}>
          Cancel
        </Button>
        <Button key="continue" variant={confirmVariant} type="submit" form={formId}>
          Prepare confirmation
        </Button>
      </>
    )
  } else if ((state.phase === 'review' || state.phase === 'asking') && def) {
    const shown = state.phase === 'asking' ? state.prepared : firstPrepared(def)
    body = (
      <>
        {def.intro ? <p>{def.intro}</p> : null}
        {def.about ? <Facts items={def.about} /> : null}
        {def.warning ? <Notice kind="warning">{def.warning}</Notice> : null}
        <Authorizing prepared={shown} />
        <p className={styles.hint}>Prepare the passkey confirmation. Nothing changes until you confirm here and the service verifies your assertion.</p>
      </>
    )
    footer = (
      <>
        <Button key="cancel" onClick={close}>
          Cancel
        </Button>
        <Button key="continue" variant={confirmVariant} disabled={state.phase === 'asking'} onClick={() => void continueToPasskey(shown)} autoFocus>
          {state.phase === 'asking' ? 'Preparing confirmation...' : 'Prepare confirmation'}
        </Button>
      </>
    )
  } else if (state.phase === 'waiting') {
    const link = state.waiting.link
    body = (
      <>
        {def?.about ? <Facts items={def.about} /> : null}
        {state.prepared ? <Authorizing prepared={state.prepared} signed={state.waiting.parameters ?? undefined} /> : <p className={styles.summary}>{state.waiting.summary}</p>}
        <Notice kind="info" title={state.waiting.proof ? 'Review before confirming' : 'Checking the authorization'}>
          {state.waiting.proof ? <p>The service prepared this passkey challenge for the operation shown above. Confirm this change to open the browser passkey prompt. The service applies it only after verification.</p> : <p>This page was reloaded while the passkey request was in progress. The service is checking what became of it. Cancel and start again if it is still pending.</p>}
        </Notice>
        {link ? (
          <p>
            <ButtonLink href={link} variant="secondary">
              Return to the passkey page
            </ButtonLink>
          </p>
        ) : null}
      </>
    )
    footer = (
      <><Button key="cancel" onClick={cancelWaiting}>Cancel the request</Button>{state.waiting.proof ? <Button key="confirm" variant={confirmVariant} onClick={() => void confirmInline(state.waiting)}>Confirm this change</Button> : null}</>
    )
  } else if (state.phase === 'done') {
    const next = safeLink(state.result.link)
    body = (
      <>
        <Notice kind="ok" title="Done">
          {state.summary}
        </Notice>
        {state.result.invitation ? <BundleOnce invitation={state.result.invitation} /> : null}
        {state.result.invitationGone ? (
          <Notice kind="warning" title="This invitation was already shown">
            The invitation was made, but it was shown before (or was not collected in time) and cannot be shown again. Revoke it in the invitation list and create a new one.
          </Notice>
        ) : null}
        {state.result.outcome === 'started' ? (
          next ? (
            <p>
              The operation continues on its own passkey pages.{' '}
              <ButtonLink href={next} variant="primary">
                Continue to the next passkey page
              </ButtonLink>
            </p>
          ) : (
            <p>The operation continues on its own passkey pages.</p>
          )
        ) : null}
      </>
    )
    footer = (
      <Button key="close" variant="primary" onClick={close} autoFocus>
        Close
      </Button>
    )
  } else {
    const failed = state as Extract<State, { phase: 'failed' }>
    body = (
      <>
        <ProblemAlert error={failed.error} title="The change was not made" />
        <p>Nothing was changed by this attempt unless the message above says so. Every change needs its own new passkey tap.</p>
      </>
    )
    footer = (
      <>
        <Button key="close" onClick={close}>
          Close
        </Button>
        {failed.prepared && def ? (
          <Button key="again" variant="primary" onClick={() => dispatch({ type: 'again', hasFields })}>
            Start over
          </Button>
        ) : null}
      </>
    )
  }

  const stepName = state.phase === 'asking' ? 'review' : state.phase

  return (
    <Dialog title={title} onCancel={close} footer={footer} step={stepName}>
      <p className="visually-hidden" role="status" aria-live="polite">
        {state.phase === 'form'
          ? 'Enter the details, then continue to the passkey page.'
          : state.phase === 'review'
            ? 'Check what will be authorized, then continue to the passkey page.'
            : state.phase === 'waiting'
              ? 'Waiting for your passkey tap.'
              : state.phase === 'done'
                ? 'Done.'
                : state.phase === 'failed'
                  ? 'The change was not made.'
                  : ''}
      </p>
      {body}
    </Dialog>
  )
}

function firstPrepared(def: OperationDef): Prepared {
  const result = def.prepare({})
  if ('errors' in result) throw new Error('an operation without fields must always prepare')

  return result
}

/** The operation and every parameter, by name, once: before the service answered, what this page will ask for; after, what the passkey signs (the service's own list). */
function Authorizing({ prepared, signed }: { prepared: Prepared; signed?: ReadonlyArray<{ name: string; value: string }> }) {
  const entries: Array<[string, string]> = signed ? signed.map((item) => [item.name, item.value]) : Object.entries(prepared.parameters).map(([name, value]) => [name, String(value)])

  return (
    <div className={styles.authorizing}>
      <h3>{signed ? 'What your passkey authorizes' : 'What will be authorized'}</h3>
      <p className={styles.summary}>{prepared.summary}</p>
      <dl className={styles.params}>
        <div>
          <dt>Operation</dt>
          <dd>
            <code>{prepared.operation}</code>
          </dd>
        </div>
        {entries.map(([name, value]) => (
          <div key={name}>
            <dt>{name}</dt>
            <dd>
              <code>{value}</code>
            </dd>
          </div>
        ))}
        {entries.length === 0 ? (
          <div>
            <dt>Parameters</dt>
            <dd>none</dd>
          </div>
        ) : null}
      </dl>
    </div>
  )
}
