import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError, api } from '../../api/client'
import { keys, useApproval } from '../../api/queries'
import type { ApprovalChallenge, ApprovalDetail, ApprovalReview } from '../../api/types'
import { Button } from '../../components/Button'
import { Facts } from '../../components/Card'
import { Dialog } from '../../components/Dialog'
import { Loading, Notice, ProblemAlert, useAnnounce } from '../../components/Feedback'
import { flash } from '../../components/Flash'
import { SplitButton } from '../../components/SplitButton'
import { Time } from '../../lib/format'
import { approveOnceChallenge, fromBase64Url, toBase64Url } from '../../lib/passkey'
import { usePollInterval } from '../authorization/poll'
import styles from './ApprovalDialog.module.css'

/** The pause before Approve can be used, so that a request is read before it is approved. */
const APPROVE_DELAY_MS = 2000

type Prepared = { challenge: ApprovalChallenge; signed: Map<number, Uint8Array<ArrayBuffer>>; rpId: string; timeout: number }

/** What the service made for this request: the bytes the passkey signs are derived here, before the tap, so that the tap itself can start the passkey prompt at once. */
async function prepare(challenge: ApprovalChallenge, minutes: readonly number[]): Promise<Prepared> {
  const payload = challenge.payload as { bind?: unknown; rpId?: unknown; timeout?: unknown }
  if (typeof payload.bind !== 'string' || typeof payload.rpId !== 'string' || typeof payload.timeout !== 'number') {
    throw new ApiError(0, 'challenge-invalid', 'Passkey unavailable', 'The service did not prepare a usable passkey challenge. Nothing was approved.')
  }
  const bind = fromBase64Url(payload.bind)

  const signed = new Map<number, Uint8Array<ArrayBuffer>>()
  for (const time of minutes) signed.set(time, await approveOnceChallenge(bind, time))

  return { challenge, signed, rpId: payload.rpId, timeout: payload.timeout }
}

function failure(error: unknown): unknown {
  if (error instanceof ApiError) return error
  return new ApiError(0, 'passkey-failed', 'Passkey not used', 'The passkey could not be used. Nothing was approved.')
}

/** A time as a person says it: "Once", "10 minutes", "1 hour", "Always". */
/** The value the authority uses for a grant with no end. */
export const ALWAYS = 1_000_000

export function timeLabel(minutes: number): string {
  if (minutes === 0) return 'Once'
  if (minutes === ALWAYS) return 'Always'
  if (minutes > 1440 && minutes % 1440 === 0) return minutes / 1440 + ' days'
  if (minutes % 60 === 0) return minutes === 60 ? '1 hour' : `${minutes / 60} hours`

  return `${minutes} minutes`
}

/** Lines the passkey signs that are for the authority to check, not for a person to read: shown under More details. */
const evidenceLine = /^(Security revision|Grant scope|Grant contents): /

function machineName(detail: ApprovalDetail): string {
  return detail.machine ? (detail.machine.friendlyName ?? detail.machine.hostName) : 'A machine'
}

/** Long code scrolls, so keyboard users must be able to focus it to read the rest. */
function CodeBlock({ children }: { children: React.ReactNode }) {
  return (
    // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- a scrollable region has to be focusable
    <pre className={styles.code} tabIndex={0}>
      {children}
    </pre>
  )
}

/** A plain headed block: the dialog is already the box. */
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className={styles.sectionTitle}>{title}</h3>
      {children}
    </section>
  )
}

function Script({ title, script }: { title: string; script: NonNullable<ApprovalReview['script']> }) {
  return (
    <Section title={title}>
      {script.binary ? <p>This file is binary; its contents are not shown.</p> : script.text !== null ? <CodeBlock>{script.text}</CodeBlock> : <p>The contents could not be read.</p>}
    </Section>
  )
}

/** One run request in a dialog over the Access screen: what would run and why, then Deny or Approve once. */
export function ApprovalDialog({ requestId, onClose }: { requestId: string; onClose: () => void }) {
  const announce = useAnnounce()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const poll = usePollInterval()
  const approval = useApproval(requestId, poll * 3)
  const detail = approval.data
  const pending = detail?.status === 'pending' && detail.review !== null
  const [prepared, setPrepared] = useState<Prepared | null>(null)
  const [problem, setProblem] = useState<unknown>(null)
  // Backing out of the passkey prompt is not a failure: it is said quietly, and the page is ready again.
  const [cancelled, setCancelled] = useState(false)
  const [phase, setPhase] = useState<'idle' | 'tapping' | 'sending' | 'denying'>('idle')
  const [ready, setReady] = useState(false)
  const times = detail?.review?.times ?? null
  const allowOnce = detail?.review?.allowOnce ?? true
  const timed = times !== null && times.length > 0
  // Once (0) first when the request may run once; a request that only makes a grant has the times alone.
  const choices = useMemo(() => (times !== null && times.length > 0 ? (allowOnce ? [0, ...times] : times) : [0]), [times, allowOnce])
  const passkeyAbort = useRef<AbortController | null>(null)
  const busy = useRef(false)

  // Approve may be used a moment after the request is shown.
  useEffect(() => {
    if (!pending) return
    const timer = setTimeout(() => setReady(true), APPROVE_DELAY_MS)

    return () => clearTimeout(timer)
  }, [pending, requestId])

  // The passkey challenge is asked for as the request opens (asking changes nothing), and again when it runs out.
  const expires = prepared?.challenge.expiresAt
  // Deny drains requests already in flight before deciding the approval.
  const challengeRequests = useRef(new Set<Promise<void>>())
  const prepareChallenge = useCallback(async () => {
    const run = (async () => {
      try {
        const challenge = await api.post('/api/v1/approvals/{requestId}/challenge', { path: { requestId } })
        setPrepared(await prepare(challenge, choices))
      } catch (error) {
        setProblem(failure(error))
      }
    })()
    const requests = challengeRequests.current
    requests.add(run)
    try {
      await run
    } finally {
      requests.delete(run)
    }
  }, [requestId, choices])
  useEffect(() => {
    if (!pending || phase !== 'idle' || busy.current) return
    if (prepared === null) {
      void prepareChallenge()

      return
    }
    const wait = new Date(expires as string).getTime() - Date.now() - 5000
    const timer = setTimeout(() => setPrepared(null), Math.max(wait, 0))

    return () => clearTimeout(timer)
  }, [pending, phase, prepared, expires, prepareChallenge])

  async function approve(minutes: number) {
    if (!prepared || busy.current) return
    busy.current = true
    setProblem(null)
    setCancelled(false)
    setPhase('tapping')
    announce('Waiting for your passkey.')
    const controller = new AbortController()
    passkeyAbort.current = controller
    try {
      // The click itself starts the passkey prompt: nothing is awaited before it. The tap releases no key (the authority decrypts with the keys its unlock opened).
      const options: PublicKeyCredentialRequestOptions = { challenge: prepared.signed.get(minutes)!, rpId: prepared.rpId, timeout: prepared.timeout, userVerification: 'required' }
      const credential = (await navigator.credentials.get({ publicKey: options, signal: controller.signal })) as PublicKeyCredential | null
      if (credential === null) throw new DOMException('cancelled', 'NotAllowedError')
      const response = credential.response as AuthenticatorAssertionResponse
      const body: { flowId: string; minutes?: number; proof: { id: string; authenticatorData: string; clientDataJSON: string; signature: string } } = {
        flowId: prepared.challenge.flowId,
        ...(timed ? { minutes } : {}),
        proof: { id: toBase64Url(credential.rawId), authenticatorData: toBase64Url(response.authenticatorData), clientDataJSON: toBase64Url(response.clientDataJSON), signature: toBase64Url(response.signature) },
      }
      setPhase('sending')
      await api.post('/api/v1/approvals/{requestId}/approve', { path: { requestId }, body })
      // Back to the list the person came from, with what happened said at the top: no extra click to get there.
      const who = detail?.review ? (detail.review.machine.friendlyName ?? detail.review.machine.hostName) : 'the machine'
      if (minutes > 0) {
        // The list this opens must show the new grant, not what it held before.
        await queryClient.invalidateQueries({ queryKey: keys.grants })
        navigate('/access', { state: flash(allowOnce ? `Approved. ${who} can run it now and again ${minutes === ALWAYS ? 'at any time' : 'for ' + timeLabel(minutes)}.` : `Grant created for ${who}.`) })
      } else {
        navigate('/access', { state: flash(`Approved. ${who} can run it now.`) })
      }
    } catch (error) {
      if (error instanceof DOMException && ['AbortError', 'NotAllowedError', 'Canceled'].includes(error.name)) setCancelled(true)
      else setProblem(failure(error))
      // A proof is accepted once: a refused or failed attempt needs a fresh challenge.
      setPrepared(null)
    } finally {
      passkeyAbort.current = null
      busy.current = false
      setPhase('idle')
      await queryClient.invalidateQueries({ queryKey: keys.approvals })
    }
  }

  async function deny() {
    if (busy.current) return
    busy.current = true
    setProblem(null)
    setPhase('denying')
    try {
      await Promise.all(challengeRequests.current)
      await api.post('/api/v1/approvals/{requestId}/deny', { path: { requestId } })
      navigate('/access', { state: flash('Denied.') })
    } catch (error) {
      setProblem(failure(error))
    } finally {
      busy.current = false
      setPhase('idle')
      await queryClient.invalidateQueries({ queryKey: keys.approvals })
    }
  }

  const d = detail
  const review = detail?.review ?? null
  const tapping = phase === 'tapping'

  if (!d || d.status !== 'pending' || !review) {
    const words = d && { approved: 'Approved.', denied: 'Denied.', expired: 'This request expired.', cancelled: 'The machine withdrew this request.', pending: 'This request is no longer available.' }[d.status]

    return (
      <Dialog
        title={d ? 'Run request from ' + machineName(d) : 'Run request'}
        onCancel={onClose}
        footer={
          <Button variant="primary" onClick={onClose} autoFocus>
            Close
          </Button>
        }
      >
        {approval.isPending ? <Loading what="the request" /> : null}
        {approval.isError ? <ProblemAlert error={approval.error} title="The request could not be read" /> : null}
        {words ? <Notice kind={d.status === 'approved' ? 'ok' : 'info'}>{words}</Notice> : null}
      </Dialog>
    )
  }

  const who = review.machine.friendlyName ?? review.machine.hostName
  const onCancel = tapping ? () => passkeyAbort.current?.abort() : phase === 'idle' ? onClose : () => undefined

  return (
    <Dialog
      title={'Run request from ' + who}
      onCancel={onCancel}
      footer={
        tapping ? (
          <Button onClick={onCancel}>Cancel</Button>
        ) : (
          <>
            <Button onClick={onClose} disabled={phase !== 'idle'}>
              Close
            </Button>
            {/* Deny is the safe default of a decision, so it holds the focus. */}
            <Button variant="danger" onClick={() => void deny()} disabled={phase !== 'idle'} autoFocus>
              Deny
            </Button>
            <SplitButton
              label={phase === 'sending' ? 'Approving...' : allowOnce ? 'Approve once' : choices[0] === ALWAYS ? 'Approve always' : 'Approve for ' + timeLabel(choices[0]!)}
              onPress={() => void approve(choices[0]!)}
              items={choices.slice(1).map((time) => ({ label: time === ALWAYS ? 'Approve always' : 'Approve for ' + timeLabel(time), onSelect: () => void approve(time) }))}
              menuLabel="Approve for longer"
              disabled={phase !== 'idle' || !ready || prepared === null}
            />
          </>
        )
      }
    >
      {review.heading ? <Notice kind="warning">{review.heading}</Notice> : null}
      {review.codeChangeWarnings.length > 0 ? (
        <div role="region" aria-label="Code changes">
          <Notice kind="warning" title="This changes how the program loads code or where it sends data">
            <ul className={styles.warnings}>
              {review.codeChangeWarnings.map((warning) => (
                <li key={warning.name}>
                  <code>{warning.value ? `${warning.name}=${warning.value}` : warning.name}</code>
                  <br />
                  {warning.why}
                </li>
              ))}
            </ul>
          </Notice>
        </div>
      ) : null}
      <Facts
        stacked
        items={[
          ['Runs', <code key="run">{[review.resolvedProgram, ...review.arguments].join(' ')}</code>],
          ['Secrets', review.secretNames.join(', ')],
          ['Reason', review.reason],
        ]}
      />
      {review.extraLines
        .filter((line) => !evidenceLine.test(line))
        .map((line) => (
          <p key={line}>{line}</p>
        ))}
      {review.shownEnvValues.length > 0 ? (
        <Section title="Other variables from .env">
          <ul className={styles.warnings}>
            {review.shownEnvValues.map((item) => (
              <li key={item.name}>
                <code>{item.name}={item.value}</code>
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
      {/* One line of inline code is already in the Runs line; the card is for code that needs reading on its own. */}
      {review.inlineCode?.includes('\n') ? (
        <Section title="Code">
          <CodeBlock>{review.inlineCode}</CodeBlock>
        </Section>
      ) : null}
      {review.script ? <Script title="Script" script={review.script} /> : null}
      {review.programFile && review.programFile.text !== null ? <Script title="Program file" script={review.programFile} /> : null}
      {review.script || (review.programFile && review.programFile.text !== null) ? (
        <p>The review covers the listed files. The command can load or run other files as they exist at run time.</p>
      ) : null}
      <details className={styles.details}>
        <summary>More details</summary>
        <Facts
          items={[
            ['Folder', <code key="folder">{review.workingDirectory}</code>],
            ['Expires', <Time key="expires" value={review.expiresAt} />],
            ['Request', <code key="id">{review.requestId}</code>],
            ...review.extraLines.filter((line) => evidenceLine.test(line)).map((line) => [line.slice(0, line.indexOf(': ')), <code key={line}>{line.slice(line.indexOf(': ') + 2)}</code>] as const),
            ['Machine fingerprint', <code key="fp">{review.machine.fingerprint}</code>],
            ['Request digest', <code key="digest">{review.requestDigest}</code>],
            ...(review.script ? ([['Script SHA-256', <code key="sha">{review.script.sha256}</code>]] as const) : []),
            ...(review.envFiles.length > 0 ? ([['Environment files', review.envFiles.join(', ')]] as const) : []),
            ...(review.inheritedEnvironmentLine ? ([['Environment', review.inheritedEnvironmentLine]] as const) : []),
          ]}
        />
      </details>
      {problem ? <ProblemAlert error={problem} title="Not approved" /> : null}
      {cancelled && !problem ? <p role="status">Passkey prompt cancelled. Nothing was approved.</p> : null}
      {tapping ? <Notice kind="info">Use your passkey in the prompt.</Notice> : null}
    </Dialog>
  )
}
