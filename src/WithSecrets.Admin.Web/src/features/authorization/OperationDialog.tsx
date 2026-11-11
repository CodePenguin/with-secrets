import { useEffect, useId, useReducer, useRef, useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError, api } from '../../api/client'
import type { Authorization, MutationResponse } from '../../api/types'
import { Button, ButtonLink } from '../../components/Button'
import { Dialog } from '../../components/Dialog'
import { Field, checkClass, controlClass } from '../../components/Field'
import { Facts } from '../../components/Card'
import { Notice, ProblemAlert, useAnnounce } from '../../components/Feedback'
import { BundleOnce } from '../pairing/BundleOnce'
import { usePollInterval } from './poll'
import type { FormValues, OperationDef, Prepared } from './operations'
import styles from './OperationDialog.module.css'

type State =
  | { phase: 'form'; values: FormValues; errors: Record<string, string> }
  | { phase: 'review'; values: FormValues; prepared: Prepared }
  | { phase: 'asking'; values: FormValues; prepared: Prepared }
  | { phase: 'waiting'; values: FormValues; prepared: Prepared; authorization: Authorization }
  | { phase: 'applying'; values: FormValues; prepared: Prepared; authorization: Authorization }
  | { phase: 'done'; prepared: Prepared; result: MutationResponse }
  | { phase: 'failed'; error: unknown; values: FormValues; prepared: Prepared | null }

type Action =
  | { type: 'reviewed'; prepared: Prepared; values: FormValues }
  | { type: 'invalid'; errors: Record<string, string>; values: FormValues }
  | { type: 'back'; values: FormValues }
  | { type: 'asking' }
  | { type: 'created'; authorization: Authorization }
  | { type: 'verified' }
  | { type: 'done'; result: MutationResponse }
  | { type: 'failed'; error: unknown }

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'reviewed':
      return { phase: 'review', values: action.values, prepared: action.prepared }
    case 'invalid':
      return { phase: 'form', values: action.values, errors: action.errors }
    case 'back':
      return { phase: 'form', values: action.values, errors: {} }
    case 'asking':
      return state.phase === 'review' ? { ...state, phase: 'asking' } : state
    case 'created':
      return state.phase === 'asking' ? { phase: 'waiting', values: state.values, prepared: state.prepared, authorization: action.authorization } : state
    case 'verified':
      return state.phase === 'waiting' ? { ...state, phase: 'applying' } : state
    case 'done':
      return state.phase === 'applying' ? { phase: 'done', prepared: state.prepared, result: action.result } : state
    case 'failed': {
      const prepared = 'prepared' in state ? state.prepared : null
      const values = 'values' in state ? state.values : {}

      return { phase: 'failed', error: action.error, values, prepared }
    }
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
 * example the full fingerprint or the host name), so they are shown to the person, not compared: the service itself refuses the mutation unless it repeats exactly what was authorized.
 */
function sameOperation(requested: Prepared, got: Authorization): boolean {
  return got.operation === requested.operation
}

type Props = { def: OperationDef; onClose: () => void }

/**
 * One administrative change from start to end, in one modal dialog:
 * 1. the form (when the change takes input) and a review that names the exact operation and every parameter the passkey will authorize;
 * 2. a request for the authorization (nothing changes), whose one-use passkey page the person opens and taps on (the page the service serves);
 * 3. when the tap is verified, the one mutation that carries the authorization id (every change needs its own; nothing is reused).
 * The page sets no time limit of its own: it waits as long as the person needs. The service's own limits are shown as they come.
 */
export function OperationDialog({ def, onClose }: Props) {
  const queryClient = useQueryClient()
  const announce = useAnnounce()
  const pollMs = usePollInterval()
  const formId = useId()
  const initial: State = def.fields?.length ? { phase: 'form', values: def.initial ?? {}, errors: {} } : { phase: 'review', values: {}, prepared: firstPrepared(def) }
  const [state, dispatch] = useReducer(reducer, initial)
  const applied = useRef<string | null>(null)
  const [draft, setDraft] = useState<FormValues>(def.initial ?? {})

  const authorization = state.phase === 'waiting' || state.phase === 'applying' ? state.authorization : null
  const authorizationId = authorization?.id

  // Ask for the authorization (it changes nothing by itself).
  useEffect(() => {
    if (state.phase !== 'asking') return
    const prepared = state.prepared
    let live = true
    api
      .post('/api/v1/authorizations', { body: { operation: prepared.operation, parameters: prepared.parameters } })
      .then((made) => {
        if (!live) return
        if (!sameOperation(prepared, made)) {
          dispatch({ type: 'failed', error: new ApiError(0, 'authorization-mismatch', 'Not the same operation', 'The service answered with an authorization for something other than what was asked. Nothing was done.') })
        } else {
          dispatch({ type: 'created', authorization: made })
        }
      })
      .catch((error: unknown) => live && dispatch({ type: 'failed', error }))

    return () => {
      live = false
    }
  }, [state])

  // Wait for the tap: ask where the authorization stands until it is verified (no time limit of this page's own).
  useEffect(() => {
    if (state.phase !== 'waiting') return
    const id = state.authorization.id
    let live = true
    let timer: ReturnType<typeof setTimeout> | undefined
    const look = async () => {
      try {
        const current = await api.get('/api/v1/authorizations/{id}', { path: { id } })
        if (!live) return
        if (current.state === 'verified') {
          dispatch({ type: 'verified' })
        } else if (current.state === 'pending') {
          timer = setTimeout(() => void look(), pollMs)
        } else {
          const why = current.detail ?? (current.state === 'expired' ? 'The authorization ran out before it was used.' : 'The authorization was ' + current.state + '.')
          dispatch({ type: 'failed', error: new ApiError(0, 'authorization-' + current.state, 'Authorization ' + current.state, why) })
        }
      } catch (error) {
        if (!live) return
        if (error instanceof ApiError && error.status === 0) {
          timer = setTimeout(() => void look(), pollMs * 3)
        } else {
          dispatch({ type: 'failed', error })
        }
      }
    }
    timer = setTimeout(() => void look(), pollMs)

    return () => {
      live = false
      if (timer) clearTimeout(timer)
    }
  }, [state.phase, authorizationId, pollMs]) // eslint-disable-line react-hooks/exhaustive-deps -- state.authorization is read only when the phase is waiting

  // Verified: perform the one mutation with this authorization (once).
  useEffect(() => {
    if (state.phase !== 'applying') return
    const id = state.authorization.id
    if (applied.current === id) return
    applied.current = id
    state.prepared
      .perform(id)
      .then((result) => {
        dispatch({ type: 'done', result })
        void queryClient.invalidateQueries()
      })
      .catch((error: unknown) => {
        dispatch({ type: 'failed', error })
        void queryClient.invalidateQueries()
      })
  }, [state, queryClient])

  useEffect(() => {
    const message: Partial<Record<State['phase'], string>> = {
      asking: 'Asking the service for an authorization.',
      waiting: 'Waiting for your passkey tap on the passkey page.',
      applying: 'Your passkey tap was verified. Making the change.',
      done: 'Done. ' + (state.phase === 'done' ? state.prepared.summary : ''),
      failed: 'The change was not made.',
    }
    const text = message[state.phase]
    if (text) announce(text)
  }, [state.phase]) // eslint-disable-line react-hooks/exhaustive-deps -- announced once per phase

  function submitForm(event: FormEvent) {
    event.preventDefault()
    const values = draft
    const result = def.prepare(values)
    if ('errors' in result) dispatch({ type: 'invalid', errors: result.errors, values })
    else dispatch({ type: 'reviewed', prepared: result, values })
  }

  const busy = state.phase === 'asking' || state.phase === 'applying'
  const link = authorization ? safeLink(authorization.link) : null
  const confirmVariant = def.danger ? 'danger' : 'primary'

  let body
  let footer
  if (state.phase === 'form') {
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
      </form>
    )
    footer = (
      <>
        <Button key="cancel" onClick={onClose}>
          Cancel
        </Button>
        <Button key="review" variant={confirmVariant} type="submit" form={formId}>
          Review
        </Button>
      </>
    )
  } else if (state.phase === 'review' || state.phase === 'asking') {
    body = (
      <>
        {def.intro ? <p>{def.intro}</p> : null}
        {def.about ? <Facts items={def.about} /> : null}
        {def.warning ? <Notice kind="warning">{def.warning}</Notice> : null}
        <Authorizing prepared={state.prepared} />
        <p>Your passkey will be asked for on a separate page, and it will show this same operation. Nothing changes until you tap there.</p>
      </>
    )
    footer = (
      <>
        <Button key="cancel" onClick={onClose}>
          Cancel
        </Button>
        {def.fields?.length ? (
          <Button key="back" disabled={busy} onClick={() => dispatch({ type: 'back', values: state.values })}>
            Back
          </Button>
        ) : null}
        <Button key="ask" variant={confirmVariant} disabled={busy} onClick={() => dispatch({ type: 'asking' })} autoFocus>
          {busy ? 'Asking...' : 'Ask for passkey authorization'}
        </Button>
      </>
    )
  } else if (state.phase === 'waiting' || state.phase === 'applying') {
    body = (
      <>
        <p>This is exactly what your passkey signs. Check that the passkey page shows the same thing.</p>
        <blockquote className={styles.sentence}>{state.authorization.sentence}</blockquote>
        <Authorizing prepared={state.prepared} signed={state.authorization.parameters} />
        {state.phase === 'waiting' ? (
          link ? (
            <>
              <p>
                <ButtonLink href={link} target="_blank" rel="noopener noreferrer" variant={confirmVariant} autoFocus>
                  Open the passkey page (new tab)
                </ButtonLink>
              </p>
              <p>Tap your passkey on that page, then come back here. This page waits for as long as you need and carries on by itself once the tap is verified.</p>
            </>
          ) : (
            <Notice kind="warning" title="No usable passkey page link">
              The service did not give a link to its own passkey page. Cancel and try again.
            </Notice>
          )
        ) : (
          <p>Your passkey tap was verified. Making the change now.</p>
        )}
      </>
    )
    footer = (
      <Button key="cancel" onClick={onClose} disabled={state.phase === 'applying'}>
        Cancel
      </Button>
    )
  } else if (state.phase === 'done') {
    const next = safeLink(state.result.link)
    body = (
      <>
        <Notice kind="ok" title="Done">
          {state.prepared.summary}
        </Notice>
        {state.result.invitation ? <BundleOnce invitation={state.result.invitation} /> : null}
        {state.result.outcome === 'started' ? (
          next ? (
            <p>
              The operation continues on its own passkey pages.{' '}
              <ButtonLink href={next} target="_blank" rel="noopener noreferrer" variant="primary">
                Open the next passkey page (new tab)
              </ButtonLink>
            </p>
          ) : (
            <p>The operation continues on its own passkey pages.</p>
          )
        ) : null}
      </>
    )
    footer = (
      <Button key="close" variant="primary" onClick={onClose} autoFocus>
        Close
      </Button>
    )
  } else {
    body = (
      <>
        <ProblemAlert error={state.error} title="The change was not made" />
        <p>Nothing was changed by this attempt unless the message above says so. Every change needs its own new authorization.</p>
      </>
    )
    footer = (
      <>
        <Button key="close" onClick={onClose}>
          Close
        </Button>
        {state.prepared ? (
          <Button key="again" variant="primary" onClick={() => dispatch({ type: 'reviewed', prepared: state.prepared as Prepared, values: state.values })}>
            Start over
          </Button>
        ) : null}
      </>
    )
  }

  const stepName = state.phase === 'applying' ? 'waiting' : state.phase === 'asking' ? 'review' : state.phase

  return (
    <Dialog title={def.title} onCancel={() => (state.phase === 'applying' ? undefined : onClose())} footer={footer} step={stepName}>
      <p className="visually-hidden" role="status" aria-live="polite">
        {state.phase === 'form' ? 'Step 1: enter the details.' : state.phase === 'review' ? 'Review what will be authorized.' : state.phase === 'waiting' ? 'Waiting for your passkey tap.' : state.phase === 'done' ? 'Done.' : state.phase === 'failed' ? 'The change was not made.' : ''}
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

/** The operation and every parameter, by name: what the authorization will be bound to. */
function Authorizing({ prepared, signed }: { prepared: Prepared; signed?: ReadonlyArray<{ name: string; value: string }> }) {
  // After the service has made the authorization, its own list (what the passkey signs) is shown; before, the parameters this page will ask for.
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
