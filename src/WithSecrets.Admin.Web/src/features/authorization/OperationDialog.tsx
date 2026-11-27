import { useEffect, useEffectEvent, useId, useReducer, useRef, useState, type ComponentProps, type FormEvent } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, api, setPendingAuthorization, type PendingAuthorization } from '../../api/client'
import type { Authorization, AuthorizationResult, ProviderValidation } from '../../api/types'
import { Button, ButtonLink } from '../../components/Button'
import { Dialog } from '../../components/Dialog'
import { Field, checkClass, controlClass } from '../../components/Field'
import { Facts } from '../../components/Card'
import { Notice, ProblemAlert, useAnnounce } from '../../components/Feedback'
import { fromBase64Url, prfOutput, sealPrf, toBase64Url, type SealedPrf } from '../../lib/passkey'
import { BundleOnce } from '../pairing/BundleOnce'
import { usePollInterval } from './poll'
import type { FieldDef, FormValues, OperationDef, Prepared } from './operations'
import styles from './OperationDialog.module.css'

/** What a waiting dialog knows of its authorization: after a reload only the id (the rest is read from the service). */
type Waiting = { id: string; operation: string; summary: string; done: string; link: string | null; parameters: ReadonlyArray<{ name: string; value: string }> | null; proof: { mode: string; payload: string } | null; prfKey: string | null }
type InlineProofBody = { proof: string; prf?: SealedPrf }

function LoadedSelect({ source, label, input }: {
  source: ReturnType<NonNullable<FieldDef['loadOptions']>>
  label: string
  input: ComponentProps<'select'>
}) {
  const options = useQuery({ queryKey: source.key, queryFn: ({ signal }) => source.load(signal), retry: false })
  const placeholder = options.isPending ? 'Loading…' : options.isError ? 'Could not load options' :
    options.data?.length ? `Choose a ${label.toLowerCase()}` : 'No options available'
  return (
    <>
      <select {...input} disabled={input.disabled || !options.data?.length} aria-busy={options.isPending}>
        <option value="">{placeholder}</option>
        {options.data?.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
      </select>
      {options.isError ? (
        <>
          <ProblemAlert error={options.error} title={`Could not load ${label.toLowerCase()}s`} />
          <Button type="button" variant="secondary" disabled={options.isFetching} onClick={() => { void options.refetch() }}>Try again</Button>
        </>
      ) : null}
    </>
  )
}

type State =
  | { phase: 'form'; errors: Record<string, string> }
  | { phase: 'review' }
  | { phase: 'asking'; prepared: Prepared }
  | { phase: 'waiting'; waiting: Waiting; prepared: Prepared | null }
  | { phase: 'done'; summary: string; result: AuthorizationResult }
  | { phase: 'failed'; error: unknown; prepared: Prepared | null }
  | { phase: 'uncertain'; error: unknown }

type Action =
  | { type: 'invalid'; errors: Record<string, string> }
  | { type: 'edited'; field: string }
  | { type: 'asking'; prepared: Prepared }
  | { type: 'created'; waiting: Waiting }
  | { type: 'challenge'; proof: { mode: string; payload: string }; parameters: ReadonlyArray<{ name: string; value: string }>; prfKey: string | null }
  | { type: 'done'; summary: string; result: AuthorizationResult }
  | { type: 'failed'; error: unknown }
  | { type: 'uncertain'; error: unknown }
  | { type: 'again'; hasFields: boolean }

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case 'invalid':
      return { phase: 'form', errors: action.errors }
    case 'edited': {
      if (state.phase !== 'form' || !(action.field in state.errors)) return state
      const rest = { ...state.errors }
      delete rest[action.field]

      return { phase: 'form', errors: rest }
    }
    case 'asking':
      return { phase: 'asking', prepared: action.prepared }
    case 'created':
      return { phase: 'waiting', waiting: action.waiting, prepared: state.phase === 'asking' ? state.prepared : null }
    case 'challenge':
      return state.phase === 'waiting' && state.waiting.proof === null ? { ...state, waiting: { ...state.waiting, proof: action.proof, parameters: action.parameters, prfKey: action.prfKey } } : state
    case 'done':
      return { phase: 'done', summary: action.summary, result: action.result }
    case 'failed':
      return { phase: 'failed', error: action.error, prepared: 'prepared' in state ? state.prepared : null }
    case 'uncertain':
      return { phase: 'uncertain', error: action.error }
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

/** How far the confirmation of a waiting authorization has come. Only the service settles the outcome; this is the page's progress through its own attempt. */
type Progress = 'idle' | 'confirming' | 'checking' | 'recover'

/** The truthful answer when no authoritative state can be read: this page does not know whether the change was made. */
function outcomeUnconfirmed(): ApiError {
  return new ApiError(
    0,
    'outcome-unknown',
    'Result not confirmed',
    'The service did not say if the change was made. Check the audit history.',
  )
}

/** Before the proof is sent, an unfinished prompt means exactly that: no change was made. */
function beforeProofFailure(error: unknown): unknown {
  if (error instanceof ApiError) return error
  if (error instanceof DOMException && (error.name === 'AbortError' || error.name === 'NotAllowedError' || error.name === 'Canceled')) {
    return new ApiError(0, 'passkey-cancelled', 'Passkey not completed', 'The passkey prompt was cancelled. Nothing was changed.')
  }
  return new ApiError(0, 'passkey-failed', 'Passkey not completed', 'The passkey prompt could not be completed. Nothing was changed.')
}

type Props = { def?: OperationDef; resume?: PendingAuthorization; onClose: () => void; onApplied: (operation: string, message: string) => boolean }

/**
 * One administrative change from start to finish in one modal dialog. First the SPA asks the service to prepare a one-use challenge bound to the reviewed operation. The final confirmation button directly invokes WebAuthn, then submits the assertion. The service verifies it and applies its retained operation; the SPA displays the service's result. Reloading can recover the pending authorization by id.
 */
export function OperationDialog({ def, resume, onClose, onApplied }: Props) {
  const queryClient = useQueryClient()
  const announce = useAnnounce()
  const pollMs = usePollInterval()
  const formId = useId()
  const hasFields = typeof def?.fields === 'function' || (def?.fields?.length ?? 0) > 0 || def?.fieldGroup !== undefined
  // What the dialog asks for as it opens, when nothing needs typing (or the initial values are already valid): it starts in 'asking', never showing a button that is about to be pressed for the person.
  const [auto] = useState<Prepared | null>(() => {
    if (resume || !def || def.validate || def.applyFromSession || (hasFields && !def.autoPrepare)) return null
    const first = def.prepare(def.initial ?? {})

    return 'errors' in first ? null : first
  })
  const initial: State = resume
    ? { phase: 'waiting', waiting: { id: resume.id, operation: resume.operation, summary: resume.summary, done: resume.done, link: null, parameters: null, proof: null, prfKey: null }, prepared: null }
    : auto
      ? { phase: 'asking', prepared: auto }
      : hasFields
        ? { phase: 'form', errors: {} }
        : { phase: 'review' }
  const [state, dispatch] = useReducer(reducer, initial)
  const [draft, setDraft] = useState<FormValues>(def?.initial ?? {})
  const [validation, setValidation] = useState<ProviderValidation | null>(null)
  const [validationError, setValidationError] = useState<unknown>(null)
  const [validating, setValidating] = useState(false)
  const [acceptWarnings, setAcceptWarnings] = useState(false)
  const validationRequest = useRef<AbortController | null>(null)
  const [progress, setProgress] = useState<Progress>('idle')
  const [recoveryError, setRecoveryError] = useState<unknown>(null)
  // The person backed out of the passkey prompt: the request is still ready, and the page says so quietly (not as a failure).
  const [promptCancelled, setPromptCancelled] = useState(false)
  const mounted = useRef(true)
  const passkeyAbort = useRef<AbortController | null>(null)
  // Synchronous guards: React state has not necessarily rendered by the time a second click arrives.
  const confirming = useRef(false)
  const proofPostInFlight = useRef(false)
  const cancelInFlight = useRef(false)
  // True from the moment the assertion is handed to the proof POST: from then on the service may have applied the operation.
  const proofAttempted = useRef(false)
  const retainedProof = useRef<{ id: string; body: InlineProofBody } | null>(null)
  const autoStarted = useRef(false)
  const promptedOnOpen = useRef(false)

  useEffect(() => {
    mounted.current = true

    return () => {
      mounted.current = false
      validationRequest.current?.abort()
    }
  }, [])

  // A change that needs nothing typed (or whose defaults are already valid) asks the service for its challenge as the dialog opens, so the only click left is the confirmation.
  // Asking for a challenge is not a passkey prompt: the prompt still starts only from the person's click on the confirm button.
  useEffect(() => {
    if (autoStarted.current || !auto) return
    autoStarted.current = true
    void continueToPasskey(auto)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps -- once, when the dialog opens

  const waiting = state.phase === 'waiting' ? state.waiting : null
  const waitingId = waiting?.id
  const waitingDone = waiting?.done ?? ''
  const waitingOperation = waiting?.operation
  const title = def?.title ?? resume?.title ?? ''
  const showApplied = useEffectEvent(onApplied)

  // A different authorization (or none) starts a fresh attempt: no guard or retained proof may leak across it.
  useEffect(() => {
    confirming.current = false
    proofPostInFlight.current = false
    cancelInFlight.current = false
    proofAttempted.current = false
    retainedProof.current = null
    setProgress('idle')
    setRecoveryError(null)
    setPromptCancelled(false)
  }, [waitingId])

  const promptForChoice = useEffectEvent((ready: Waiting) => { void confirmInline(ready) })
  useEffect(() => {
    if (!def?.promptOnOpen || !waiting?.proof || promptedOnOpen.current) return
    promptedOnOpen.current = true
    promptForChoice(waiting)
  }, [def?.promptOnOpen, waiting])

  // Checking cannot go on unspoken forever: after a bounded time the page offers a safe way out while it keeps reconciling.
  useEffect(() => {
    if (state.phase !== 'waiting' || progress !== 'checking') return
    const timer = setTimeout(() => setProgress('recover'), Math.max(pollMs * 20, 300))

    return () => clearTimeout(timer)
  }, [state.phase, progress, pollMs, waitingId])

  // Wait for the tap: ask where the authorization stands, and what came of it, until it is settled (no time limit of this page's own).
  useEffect(() => {
    if (!waitingId) return
    let live = true
    let timer: ReturnType<typeof setTimeout> | undefined
    const settle = (action: Action) => {
      if (!live) return
      // A definitive state (or a deliberately recoverable one) ends the attempt's guard.
      confirming.current = false
      proofPostInFlight.current = false
      retainedProof.current = null
      setProgress('idle')
      setPendingAuthorization(null)
      void queryClient.invalidateQueries()
      if (action.type === 'done' && action.result.outcome === 'applied' && !action.result.invitation && !action.result.invitationGone && waitingOperation &&
          showApplied(waitingOperation, action.result.detail ?? action.summary)) return
      dispatch(action)
    }
    const outcomeUnknown = async () => {
      // A lock ends every session and authorization, this one included. The public status then says whether the authority is locked: that is the answer the person wanted.
      if (waitingOperation === 'lock') {
        try {
          const status = await api.get('/api/v1/status')
          if (!live) return
          if (status.locked) {
            settle({ type: 'done', summary: 'The authority is locked.', result: { outcome: 'applied', code: null, detail: null, link: null, invitation: null, invitationGone: false } })

            return
          }
        } catch {
          // Not readable: fall through to the honest uncertainty.
        }
      }
      if (live) settle({ type: 'uncertain', error: outcomeUnconfirmed() })
    }
    const look = async () => {
      try {
        const current = await api.get('/api/v1/authorizations/{id}', { path: { id: waitingId }, query: { collect: 'invitation' } })
        if (!live) return
        if (current.state === 'consumed' && current.result) {
          const result = current.result
          if (result.outcome === 'failed') {
            settle({ type: 'failed', error: new ApiError(0, result.code ?? 'operation-failed', 'The change was not made', result.detail ?? 'Your passkey was accepted, but the change could not be made.') })
          } else {
            settle({ type: 'done', summary: waitingDone, result })
          }
        } else if (current.state === 'pending' && current.proof) {
          dispatch({ type: 'challenge', proof: current.proof, parameters: current.parameters, prfKey: current.prfKey })
          timer = setTimeout(() => void look(), pollMs)
        } else if (current.state === 'pending' || current.state === 'verified' || current.state === 'consumed') {
          timer = setTimeout(() => void look(), pollMs)
        } else {
          const why = current.detail ?? (current.state === 'expired' ? 'The authorization ran out before it was used.' : 'The authorization was ' + current.state + '.')
          settle({ type: 'failed', error: new ApiError(0, 'authorization-' + current.state, 'Authorization ' + current.state, why) })
        }
      } catch (error) {
        if (!live) return
        if (error instanceof ApiError && (error.status === 0 || error.status >= 500)) {
          // The status endpoint is unavailable: keep reconciling, but never turn that into a claim about the change.
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
      done: state.phase === 'done' ? state.summary : '',
      failed: 'The change was not made.',
      uncertain: 'The outcome could not be confirmed.',
    }
    const text = message[state.phase]
    if (text) announce(text)
  }, [state.phase]) // eslint-disable-line react-hooks/exhaustive-deps -- announced once per phase

  useEffect(() => {
    if (state.phase !== 'waiting') return
    const text =
      progress === 'confirming'
        ? 'Waiting for your passkey.'
        : progress === 'checking'
          ? 'Checking the result of your passkey confirmation.'
          : progress === 'recover'
            ? 'The result of your passkey confirmation is not confirmed yet.'
            : ''
    if (text) announce(text)
  }, [progress, state.phase]) // eslint-disable-line react-hooks/exhaustive-deps -- announced once per progress step

  /** Prepare the service-owned, operation-bound challenge. No operation is applied yet. */
  async function continueToPasskey(prepared: Prepared) {
    dispatch({ type: 'asking', prepared })
    try {
      const made = await api.post('/api/v1/authorizations/inline', { body: { operation: prepared.operation, parameters: prepared.parameters, ...(def?.applyFromSession ? { applyFromSession: true } : {}) } })
      if (!mounted.current) {
        if (made.state === 'pending') cancelAuthorization(made.id)
        else void queryClient.invalidateQueries()

        return
      }
      if (!sameOperation(prepared, made)) {
        cancelAuthorization(made.id)
        dispatch({ type: 'failed', error: new ApiError(0, 'authorization-mismatch', 'Not the same operation', 'The service answered for a different request. Nothing was done.') })

        return
      }
      if (def?.applyFromSession && made.state === 'consumed' && made.result) {
        void queryClient.invalidateQueries()
        if (made.result.outcome === 'applied') {
          const summary = made.result.detail ?? prepared.done
          if (!onApplied(prepared.operation, summary)) dispatch({ type: 'done', summary, result: made.result })
        } else {
          dispatch({ type: 'failed', error: new ApiError(0, made.result.code ?? 'operation-failed', 'The change was not made', made.result.detail ?? 'The service refused the change.') })
        }
        return
      }
      if (!made.proof || made.proof.mode !== 'webauthn') {
        cancelAuthorization(made.id)
        dispatch({ type: 'failed', error: new ApiError(0, 'proof-unavailable', 'Passkey unavailable', 'The service did not prepare a usable passkey challenge. Nothing was changed.') })
        return
      }
      setPendingAuthorization({ id: made.id, operation: made.operation, title, summary: prepared.summary, done: prepared.done })
      dispatch({ type: 'created', waiting: { id: made.id, operation: made.operation, summary: prepared.summary, done: prepared.done, link: null, parameters: made.parameters, proof: made.proof, prfKey: made.prfKey } })
    } catch (error) {
      if (mounted.current) dispatch({ type: 'failed', error })
    }
  }

  /** The click itself synchronously calls WebAuthn before any network request or await. */
  async function confirmInline(waiting: Waiting) {
    if (!waiting.proof || confirming.current) return
    // The ref is set before the first await, so a second click cannot start a second ceremony while React has yet to re-render.
    confirming.current = true
    proofAttempted.current = false
    retainedProof.current = null
    setRecoveryError(null)
    setPromptCancelled(false)
    setProgress('confirming')
    const controller = new AbortController()
    passkeyAbort.current = controller
    let body: InlineProofBody
    try {
      const payload = JSON.parse(waiting.proof.payload) as { bind: string; rpId: string; timeout: number; salt?: string | null }
      const challenge = fromBase64Url(payload.bind)
      const options: PublicKeyCredentialRequestOptions = { challenge, rpId: payload.rpId, timeout: payload.timeout, userVerification: 'required' }
      if (waiting.prfKey && payload.salt) options.extensions = { prf: { eval: { first: fromBase64Url(payload.salt) } } }
      const credentialPromise = navigator.credentials.get({ publicKey: options, signal: controller.signal })
      const credential = await credentialPromise
      if (credential === null) throw new ApiError(0, 'passkey-cancelled', 'Passkey not completed', 'The passkey prompt was cancelled. Nothing was changed.')
      const assertion = credential as PublicKeyCredential
      const response = assertion.response as AuthenticatorAssertionResponse
      body = { proof: JSON.stringify({ id: toBase64Url(assertion.rawId), authenticatorData: toBase64Url(response.authenticatorData), clientDataJSON: toBase64Url(response.clientDataJSON), signature: toBase64Url(response.signature) }) }
      if (waiting.prfKey && options.extensions) {
        const output = prfOutput(assertion)
        if (output !== null) {
          try {
            body.prf = await sealPrf(output, challenge, fromBase64Url(waiting.prfKey))
          } finally {
            output.fill(0)
          }
        }
      }
    } catch (error) {
      // No proof has been sent: end this attempt.
      confirming.current = false
      setProgress('idle')
      if (error instanceof DOMException && (error.name === 'AbortError' || error.name === 'NotAllowedError' || error.name === 'Canceled')) {
        // Backing out of the prompt is not a failure: the prepared request is unused and stays ready for another try.
        setPromptCancelled(true)
        return
      }
      // Anything else ends the attempt: safely cancel the still-pending authorization.
      cancelAuthorization(waiting.id)
      setPendingAuthorization(null)
      dispatch({ type: 'failed', error: beforeProofFailure(error) })
      return
    } finally {
      if (passkeyAbort.current === controller) passkeyAbort.current = null
    }

    // From here on the service may have received the proof even if this page never sees the answer.
    proofAttempted.current = true
    retainedProof.current = { id: waiting.id, body }
    setProgress('checking')
    await submitProof(waiting.id, body)
  }

  /**
   * Send an assertion that was already made. The service binds it to the one pending authorization and accepts a proof once, so repeating this request cannot apply the operation twice:
   * afterwards the authorization is consumed with its recorded result, or the repeated proof is refused.
   */
  async function submitProof(id: string, body: InlineProofBody) {
    if (proofPostInFlight.current) return
    proofPostInFlight.current = true
    setProgress('checking')
    try {
      await api.post('/api/v1/authorizations/{id}/proof', { path: { id }, body })
    } catch {
      // Ambiguous: the service may have accepted the proof and applied the operation. Keep the guard held and let the authoritative poll decide.
      setProgress('checking')
    } finally {
      proofPostInFlight.current = false
    }
  }

  function retryProof() {
    if (!retainedProof.current) return
    void submitProof(retainedProof.current.id, retainedProof.current.body)
  }

  async function cancelAfterAttempt(waiting: Waiting) {
    if (cancelInFlight.current) return
    cancelInFlight.current = true
    setRecoveryError(null)
    try {
      await api.delete('/api/v1/authorizations/{id}', { path: { id: waiting.id } })
      // The service cancelled a request whose tap it had not judged: nothing was applied.
      confirming.current = false
      proofAttempted.current = false
      retainedProof.current = null
      setPendingAuthorization(null)
      dispatch({ type: 'failed', error: new ApiError(0, 'authorization-cancelled', 'Request cancelled', 'The request was cancelled before its passkey proof was accepted. Nothing was changed.') })
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        // The tap was already judged: read the service's answer instead of guessing from a cancellation.
        setProgress('checking')
      } else {
        // Still unresolved: say so, keep the request and its guard, and let the person try again.
        setRecoveryError(error)
      }
    } finally {
      cancelInFlight.current = false
    }
  }

  /** Back to the form: the prepared request is cancelled, so the next one is made for the edited values. */
  function changeDetails(waiting: Waiting) {
    cancelAuthorization(waiting.id)
    setPendingAuthorization(null)
    dispatch({ type: 'again', hasFields: true })
  }

  function cancelWaiting() {
    if (state.phase !== 'waiting' || progress === 'checking') return
    if (passkeyAbort.current) {
      passkeyAbort.current.abort()
      return
    }
    close()
  }

  function close() {
    if (state.phase === 'waiting') {
      if (progress === 'checking') return
      if (!proofAttempted.current) {
        // Cancelling a still-pending request cancels it at the service too: a tap on its page afterwards changes nothing.
        cancelAuthorization(state.waiting.id)
        setPendingAuthorization(null)
      }
      // A proof that may have reached the service keeps its pending record: a reload resumes reconciliation instead of starting another attempt.
    } else {
      setPendingAuthorization(null)
    }
    onClose()
  }

  function editField(field: string, value: string | boolean, clear: readonly string[] = []) {
    setDraft((current) => {
      const next = { ...current, [field]: value }
      for (const dependent of clear) delete next[dependent]
      return next
    })
    setValidation(null)
    setValidationError(null)
    setAcceptWarnings(false)
    dispatch({ type: 'edited', field })
    for (const dependent of clear) dispatch({ type: 'edited', field: dependent })
  }

  async function submitForm(event: FormEvent) {
    event.preventDefault()
    if (!def || state.phase !== 'form' || validationRequest.current) return
    const result = def.prepare(draft)
    if ('errors' in result) {
      dispatch({ type: 'invalid', errors: result.errors })
      return
    }

    if (!def.validate) {
      await continueToPasskey(result)
      return
    }

    if (validation) {
      if (validation.ok && acceptWarnings) {
        await continueToPasskey({ ...result, parameters: { ...result.parameters, 'confirm-warnings': 'yes' } })
      }
      return
    }

    const request = new AbortController()
    validationRequest.current = request
    setValidating(true)
    setValidationError(null)
    try {
      let prepared = result
      if (def.prepareForValidation) {
        const sealed = await def.prepareForValidation(prepared, draft, request.signal)
        if (request.signal.aborted) return
        prepared = sealed.prepared
        setDraft(sealed.draft)
      }
      const checked = await def.validate(prepared, request.signal)
      if (request.signal.aborted) return
      if (checked.ok && checked.issues.length === 0) await continueToPasskey(prepared)
      else setValidation(checked)
    } catch (error) {
      if (!request.signal.aborted) setValidationError(error)
    } finally {
      validationRequest.current = null
      if (!request.signal.aborted) setValidating(false)
    }
  }

  const confirmVariant = def?.danger ? 'danger' : 'primary'

  let body
  let footer
  if (state.phase === 'form' && def) {
    const formFields = typeof def.fields === 'function' ? def.fields(draft) : def.fields ?? []
    const fields = (definitions: FieldDef[], autofocus = false) =>
      definitions.filter((field) => field.visible?.(draft) ?? true).map((field, index) => (
          <Field key={field.name} label={field.label} hint={field.hint} error={state.errors[field.name]} required={field.required}>
            {(control) => {
              if (field.kind === 'checkbox') {
                return <input {...control} type="checkbox" className={checkClass} disabled={validating} checked={draft[field.name] === true} onChange={(event) => editField(field.name, event.target.checked)} />
              }

              const input = {
                ...control,
                className: controlClass,
                disabled: validating,
                value: String(draft[field.name] ?? ''),
                onChange: (event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => editField(field.name, event.target.value, field.clearOnChange),
              }
              if (field.kind === 'select') {
                if (field.loadOptions) return <LoadedSelect source={field.loadOptions(draft)} label={field.label} input={input} />
                return <select {...input}>{field.options?.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select>
              }
              if (field.kind === 'textarea') {
                return <textarea {...input} rows={5} maxLength={field.maxLength} autoComplete="off" spellCheck={false} />
              }
              if (field.suggestions?.length) {
                const list = control.id + '-options'
                return (
                  <>
                    <input {...input} type="text" list={list} maxLength={field.maxLength} autoComplete="off" spellCheck={false} />
                    <datalist id={list}>{field.suggestions.map(option => <option key={option} value={option} />)}</datalist>
                  </>
                )
              }
              // eslint-disable-next-line jsx-a11y/no-autofocus -- the first field of a modal form
              return <input {...input} type={field.kind === 'password' ? 'password' : 'text'} inputMode={field.kind === 'number' ? 'numeric' : undefined} maxLength={field.maxLength} autoComplete="off" spellCheck={false} autoFocus={autofocus && index === 0} />
            }}
          </Field>
      ))
    body = (
      <form id={formId} onSubmit={(event) => void submitForm(event)} noValidate className={styles.form}>
        {def.intro ? <p>{def.intro}</p> : null}
        {def.about ? <Facts items={def.about} /> : null}
        {def.warning ? <Notice kind="warning">{def.warning}</Notice> : null}
        {fields(formFields, true)}
        {def.fieldGroup && (def.fieldGroup.visible?.(draft) ?? true) ? (
          <fieldset className={styles.fieldGroup}>
            <legend>{def.fieldGroup.label}</legend>
            <p>{def.fieldGroup.hint}</p>
            <div className={styles.fieldGroupRow}>{fields(def.fieldGroup.fields, !formFields.length)}</div>
          </fieldset>
        ) : null}
        {validationError ? <ProblemAlert error={validationError} title="Validation could not finish" /> : null}
        {validation ? (
          <>
            <div role={validation.ok ? 'status' : 'alert'}>
              <Notice kind={validation.ok ? 'warning' : 'error'} title={validation.ok ? 'Provider warnings' : 'Fix the validation errors'}>
                <ul>{validation.issues.map((issue, index) => <li key={index}>{issue.message}</li>)}</ul>
              </Notice>
            </div>
            {validation.ok ? (
              <Field label="Continue with these warnings">
                {(control) => <input {...control} className={checkClass} type="checkbox" checked={acceptWarnings} onChange={(event) => setAcceptWarnings(event.target.checked)} />}
              </Field>
            ) : null}
          </>
        ) : null}
      </form>
    )
    footer = (
      <>
        <Button key="cancel" onClick={close}>
          Cancel
        </Button>
        <Button key="continue" variant={confirmVariant} type="submit" form={formId} disabled={validating || (validation !== null && (!validation.ok || !acceptWarnings))}>
          {validating ? 'Validating…' : 'Continue'}
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
      </>
    )
    footer = (
      <>
        <Button key="cancel" onClick={close}>
          Cancel
        </Button>
        <Button key="continue" variant={confirmVariant} disabled={state.phase === 'asking'} onClick={() => void continueToPasskey(shown)} autoFocus>
          {state.phase === 'asking' ? (def.applyFromSession ? 'Applying...' : 'Preparing...') : def.applyFromSession ? (def.confirmLabel ?? 'Confirm') : 'Continue'}
        </Button>
      </>
    )
  } else if (state.phase === 'waiting') {
    const link = state.waiting.link
    const challenge = state.waiting.proof
    const notice =
      progress === 'confirming'
        ? { kind: 'info' as const, title: 'Waiting for your passkey', text: 'Use your passkey in the prompt.' }
        : progress === 'checking'
          ? {
              kind: 'info' as const,
              title: 'Checking the result',
              text: 'Sent. Checking the result. Do not confirm again.',
            }
          : progress === 'recover'
            ? {
                kind: 'warning' as const,
                title: 'The result is not confirmed yet',
                text: retainedProof.current
                  ? 'No answer yet. Send it again (it cannot apply twice) or cancel.'
                  : 'No answer yet. Check the audit history before trying again.',
              }
            : challenge
              ? null
              : {
                  kind: 'info' as const,
                  title: 'Checking the request',
                  text: 'This page was reloaded. Checking your request. Cancel to start again.',
                }
    body = (
      <>
        {def?.intro ? <p>{def.intro}</p> : null}
        {def?.about ? <Facts items={def.about} /> : null}
        {def?.warning ? <Notice kind="warning">{def.warning}</Notice> : null}
        {state.prepared ? <Authorizing prepared={state.prepared} signed={state.waiting.parameters ?? undefined} /> : <p className={styles.summary}>{state.waiting.summary}</p>}
        {notice ? (
          <Notice kind={notice.kind} title={notice.title}>
            <p>{notice.text}</p>
          </Notice>
        ) : promptCancelled ? (
          <p role="status">Passkey prompt cancelled. Nothing was changed.</p>
        ) : null}
        {recoveryError ? <ProblemAlert error={recoveryError} title="The request could not be cancelled" /> : null}
        {link ? (
          <p>
            <ButtonLink href={link} variant="secondary">
              Return to the passkey page
            </ButtonLink>
          </p>
        ) : null}
      </>
    )
    footer =
      progress === 'confirming' ? (
        <Button key="cancel" onClick={cancelWaiting}>
          Cancel
        </Button>
      ) : progress === 'checking' ? (
        <Button key="checking" disabled>
          Checking the result...
        </Button>
      ) : progress === 'recover' ? (
        <>
          <Button key="cancel" onClick={() => void cancelAfterAttempt(state.waiting)}>
            Cancel
          </Button>
          {retainedProof.current ? (
            <Button key="retry" variant={confirmVariant} onClick={retryProof}>
              Send the same confirmation again
            </Button>
          ) : null}
        </>
      ) : (
        <>
          <Button key="cancel" onClick={cancelWaiting}>
            Cancel
          </Button>
          {challenge && def?.autoPrepare ? (
            <Button key="change" onClick={() => changeDetails(state.waiting)}>
              Change details
            </Button>
          ) : null}
          {challenge ? (
            <Button key="confirm" variant={confirmVariant} onClick={() => void confirmInline(state.waiting)} autoFocus>
              {def?.confirmLabel ?? 'Confirm with passkey'}
            </Button>
          ) : null}
        </>
      )
  } else if (state.phase === 'done') {
    const next = safeLink(state.result.link)
    body = (
      <>
        <Notice kind="ok">
          {state.result.detail ?? state.summary}
        </Notice>
        {state.result.invitation ? <BundleOnce invitation={state.result.invitation} /> : null}
        {state.result.invitationGone ? (
          <Notice kind="warning" title="This invitation was already shown">
            The invitation was made but cannot be shown again. Revoke it and create a new one.
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
  } else if (state.phase === 'uncertain') {
    body = (
      <>
        <ProblemAlert error={state.error} title="Result not confirmed" />
        <p>Check the audit history before trying again.</p>
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
  const cancelDialog =
    state.phase === 'waiting' && progress === 'checking'
      ? () => undefined
      : state.phase === 'waiting' && progress === 'confirming'
        ? cancelWaiting
        : close

  return (
    <Dialog title={title} onCancel={cancelDialog} footer={footer} step={stepName}>
      <p className="visually-hidden" role="status" aria-live="polite">
        {state.phase === 'form'
          ? 'Enter the details, then continue to the passkey page.'
          : state.phase === 'review'
            ? (def?.applyFromSession ? 'Review and confirm the change.' : 'Check what will be authorized, then continue to the passkey page.')
            : state.phase === 'waiting'
              ? progress === 'checking'
                ? 'Checking the result of your passkey confirmation.'
                : progress === 'recover'
                  ? 'The result is not confirmed yet.'
                  : progress === 'confirming'
                    ? 'Waiting for your passkey.'
                    : 'Waiting for your passkey tap.'
              : state.phase === 'done'
                ? ''
                : state.phase === 'failed'
                  ? 'The change was not made.'
                  : state.phase === 'uncertain'
                    ? 'The outcome could not be confirmed.'
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

/** What will happen, in one sentence. The operation and every parameter the passkey signs sit under Details. */
function Authorizing({ prepared, signed }: { prepared: Prepared; signed?: ReadonlyArray<{ name: string; value: string }> }) {
  const entries: Array<[string, string]> = signed ? signed.map((item) => [item.name, item.value]) : Object.entries(prepared.parameters).map(([name, value]) => [name, String(value)])

  return (
    <div className={styles.authorizing}>
      <p className={styles.summary}>{prepared.summary}</p>
      <details>
        <summary>Details</summary>
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
        </dl>
      </details>
    </div>
  )
}
