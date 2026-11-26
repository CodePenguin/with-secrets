import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { Button } from '../../components/Button'
import { Card, Facts } from '../../components/Card'
import { Loading, Notice, ProblemAlert, useAnnounce } from '../../components/Feedback'
import { removeChallenge } from '../../lib/passkey'
import { assert, failure, promptCancelled } from '../../lib/manifestProof'

const pageSettingsKey = ['page-settings'] as const

/** The settings of the pages this machine serves (a run approval, enrolling a passkey). Saving needs one admin passkey tap over the exact next state. */
export function PageSettingsCard({ canChange }: { canChange: boolean }) {
  const announce = useAnnounce()
  const queryClient = useQueryClient()
  const settings = useQuery({ queryKey: pageSettingsKey, queryFn: () => api.get('/api/v1/page-settings') })
  const [reuseMax, setReuseMax] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [port, setPort] = useState('')
  const [timeout, setTimeout] = useState('')
  const [problem, setProblem] = useState<unknown>(null)
  const [done, setDone] = useState<string | null>(null)
  const [cancelled, setCancelled] = useState(false)
  const [busy, setBusy] = useState(false)
  const working = useRef(false)
  const data = settings.data

  useEffect(() => {
    if (!data) return
    setReuseMax(String(data.reuseMaxMinutes))
    setBaseUrl(data.baseUrl ?? '')
    setPort(String(data.port))
    setTimeout(String(data.timeoutMinutes))
  }, [data])

  if (settings.isPending) return <Loading what="the page settings" />
  if (settings.isError) return <ProblemAlert error={settings.error} title="The page settings could not be read" />

  if (!canChange) {
    return (
      <Card title="Approval pages">
        <Facts items={[
          ['Longest grant time', `${settings.data.reuseMaxMinutes} minutes`],
          ['Address', settings.data.baseUrl ?? 'http://localhost'],
          ['Port', settings.data.port],
          ['Time limit', `${settings.data.timeoutMinutes} minutes`],
        ]} />
      </Card>
    )
  }

  const body = { reuseMaxMinutes: Number(reuseMax), baseUrl: baseUrl.trim() === '' ? null : baseUrl.trim(), port: Number(port), timeoutMinutes: Number(timeout) }
  const unchanged = body.reuseMaxMinutes === data?.reuseMaxMinutes && body.baseUrl === data?.baseUrl && body.port === data?.port && body.timeoutMinutes === data?.timeoutMinutes

  async function save() {
    if (working.current) return
    working.current = true
    setBusy(true)
    setProblem(null)
    setCancelled(false)
    setDone(null)
    try {
      const started = await api.post('/api/v1/page-settings/changes', { body })
      try {
        const proof = await assert(started, (b) => removeChallenge(b, started.manifest))
        await api.post('/api/v1/page-settings/changes/{id}/save', { path: { id: started.id }, body: { proof } })
      } catch (error) {
        await api.delete('/api/v1/page-settings/changes/{id}', { path: { id: started.id } }).catch(() => undefined)
        throw error
      }
      setDone('Saved the page settings.')
      announce('Saved the page settings.')
    } catch (error) {
      if (promptCancelled(error)) setCancelled(true)
      else setProblem(failure(error))
    } finally {
      working.current = false
      setBusy(false)
      await queryClient.invalidateQueries({ queryKey: pageSettingsKey })
    }
  }

  return (
    <Card title="Approval pages">
      <form
        onSubmit={(event) => {
          event.preventDefault()
          void save()
        }}
      >
        <p>
          <label htmlFor="ps-reuse">Longest grant time (minutes, 10 to 43200)</label>
          <br />
          <input id="ps-reuse" type="number" min={10} max={43200} value={reuseMax} onChange={(event) => setReuseMax(event.target.value)} />
        </p>
        <p>
          <label htmlFor="ps-url">Address of the pages (empty for http://localhost)</label>
          <br />
          <input id="ps-url" value={baseUrl} onChange={(event) => setBaseUrl(event.target.value)} autoComplete="off" spellCheck={false} maxLength={2048} />
        </p>
        <p>
          <label htmlFor="ps-port">Port (0 picks a free one)</label>
          <br />
          <input id="ps-port" type="number" min={0} max={65535} value={port} onChange={(event) => setPort(event.target.value)} />
        </p>
        <p>
          <label htmlFor="ps-timeout">Time limit of a page (minutes, 1 to 30)</label>
          <br />
          <input id="ps-timeout" type="number" min={1} max={30} value={timeout} onChange={(event) => setTimeout(event.target.value)} />
        </p>
        <p>
          <Button variant="primary" type="submit" disabled={busy || unchanged}>
            Save with a passkey...
          </Button>
        </p>
      </form>
      {done ? <Notice kind="ok">{done}</Notice> : null}
      {problem ? <ProblemAlert error={problem} title="Nothing was changed" /> : null}
      {cancelled ? <p role="status">Passkey prompt cancelled. Nothing was changed.</p> : null}
    </Card>
  )
}
