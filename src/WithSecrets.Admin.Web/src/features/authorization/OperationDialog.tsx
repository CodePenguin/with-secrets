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
type Waiting = { id: string; operation: string; summary: string; link: string | null; parameters: ReadonlyArray<{ name: string; value: string }> | null }

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
 * One administrative change from start to end, in one modal dialog and one step before the passkey page:
 * 1. the form (when the change takes input), or for a change without input the facts, and ONE button, "Continue to passkey": it asks the service for the authorization (it changes nothing by itself) and navigates
 *    this tab to the service's own one-use passkey page; the facts of the operation are shown once, as the service will have the passkey sign them;
 * 2. the person taps there, then uses browser Back to return. The SERVICE makes the change the tap authorized, when the tap is verified (single use, bound to the operation and its parameters): this page only asks what became of it. A reloaded tab finds the waiting authorization again (its id is kept in this tab's session storage) and shows its result.
 * The page sets no time limit of its own: it waits as long as the person needs. The service's own limits are shown as they come.
 */
export function OperationDialog({ def, resume, onClose }: Props) {
  const queryClient = useQueryClient()
  const announce = useAnnounce()
  const pollMs = usePollInterval()
  const formId = useId()
  const hasFields = (def?.fields?.length ?? 0) > 0
  const initial: State = resume
    ? { phase: 'waiting', waiting: { id: resume.id, operation: resume.operation, summary: resume.summary, link: null, parameters: null }, prepared: null }
    : hasFields
      ? { phase: 'form', errors: {} }
      : { phase: 'review' }
  const [state, dispatch] = useReducer(reducer, initial)
  const [draft, setDraft] = useState<FormValues>(def?.initial ?? {})
  const mounted = useRef(true)

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

  /** One step: ask the service for the authorization and navigate this tab to its passkey page. Nothing changes until the tap there. */
  async function continueToPasskey(prepared: Prepared) {
    dispatch({ type: 'asking', prepared })
    try {
      const made = await api.post('/api/v1/authorizations', { body: { operation: prepared.operation, parameters: prepared.parameters } })
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
      setPendingAuthorization({ id: made.id, operation: made.operation, title, summary: prepared.summary })
      const link = safeLink(made.link)
      dispatch({ type: 'created', waiting: { id: made.id, operation: made.operation, summary: prepared.summary, link, parameters: made.parameters } })
      if (link) window.location.assign(link)
    } catch (error) {
      if (mounted.current) dispatch({ type: 'failed', error })
    }
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
        <p className={styles.hint}>Continue opens the passkey page in this tab. Nothing changes until you tap your passkey there, and that page shows exactly what you are authorizing. Use Back to return here.</p>
      </form>
    )
    footer = (
      <>
        <Button key="cancel" onClick={close}>
          Cancel
        </Button>
        <Button key="continue" variant={confirmVariant} type="submit" form={formId}>
          Continue to passkey
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
        <p className={styles.hint}>Continue opens the passkey page in this tab. Nothing changes until you tap your passkey there. Use Back to return here.</p>
      </>
    )
    footer = (
      <>
        <Button key="cancel" onClick={close}>
          Cancel
        </Button>
        <Button key="continue" variant={confirmVariant} disabled={state.phase === 'asking'} onClick={() => void continueToPasskey(shown)} autoFocus>
          {state.phase === 'asking' ? 'Opening the passkey page...' : 'Continue to passkey'}
        </Button>
      </>
    )
  } else if (state.phase === 'waiting') {
    const link = state.waiting.link
    body = (
      <>
        {def?.about ? <Facts items={def.about} /> : null}
        {state.prepared ? <Authorizing prepared={state.prepared} signed={state.waiting.parameters ?? undefined} /> : <p className={styles.summary}>{state.waiting.summary}</p>}
        <Notice kind="info" title="Waiting for your passkey tap">
          {resume ? (
            <p>This page was reloaded while a passkey tap was waiting. It is asking the service what became of it. If you have not tapped yet, use browser Forward to return to the passkey page, or cancel this request and start again.</p>
          ) : (
            <p>Check that the passkey page names the operation above, then tap your passkey. Use Back to return here; the service makes the change when the tap is verified.</p>
          )}
        </Notice>
        {link ? (
          <p>
            <ButtonLink href={link} variant="secondary">
              Return to the passkey page
            </ButtonLink>
          </p>
        ) : resume ? null : (
          <Notice kind="warning" title="No usable passkey page link">
            The service did not give a link to its own passkey page that this page will open. Cancel and try again.
          </Notice>
        )}
      </>
    )
    footer = (
      <Button key="cancel" onClick={close}>
        Cancel the request
      </Button>
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
