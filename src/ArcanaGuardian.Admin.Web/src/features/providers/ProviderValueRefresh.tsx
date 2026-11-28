import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { Provider } from '../../api/types'
import type { components } from '../../api/schema'
import { Button } from '../../components/Button'
import { Facts } from '../../components/Card'
import { Dialog } from '../../components/Dialog'
import { Loading, Notice, ProblemAlert } from '../../components/Feedback'
import { fromBase64Url, toBase64Url } from '../../lib/passkey'
import { useStartOperation } from '../authorization/OperationProvider'
import { lastPassFields } from './providerOperations'
import styles from './ProvidersPage.module.css'

type Refresh = components['schemas']['ProviderValueRefresh']

function cancelRefresh(id: string) {
  void api.delete('/api/v1/provider-value-refreshes/{id}', { path: { id } }).catch(() => undefined)
}

function formatPath(path: string) {
  const [id, field] = path.split('/')
  return field && Object.hasOwn(lastPassFields, field) ? `Item ${id} / ${lastPassFields[field]}` : path
}

export function ProviderValueRefresh({ provider }: { provider: Provider }) {
  const startOperation = useStartOperation()
  const [open, setOpen] = useState(false)
  const [refresh, setRefresh] = useState<Refresh | null>(null)
  const [matchingCode, setMatchingCode] = useState('')
  const [error, setError] = useState<unknown>(null)
  const starting = useRef<AbortController | null>(null)
  const active = useRef<string | null>(null)

  function cancel() {
    starting.current?.abort()
    if (active.current) cancelRefresh(active.current)
    active.current = null
  }

  useEffect(() => () => cancel(), [])

  async function launch() {
    const controller = new AbortController()
    starting.current = controller
    setOpen(true)
    setError(null)
    setRefresh(null)
    setMatchingCode('')
    try {
      const subtle = globalThis.crypto.subtle
      const browserKey = await subtle.generateKey({
        name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
      }, false, ['encrypt', 'decrypt'])
      const publicKey = new Uint8Array(await subtle.exportKey('spki', browserKey.publicKey))
      if (controller.signal.aborted) return
      const { refresh: launched, encryptedCode } = await api.post('/api/v1/providers/{id}/value-refreshes', {
        path: { id: provider.id }, body: { browserKey: toBase64Url(publicKey) }, signal: controller.signal,
      })
      if (controller.signal.aborted) {
        cancelRefresh(launched.id)
        return
      }
      active.current = launched.id
      const code = new TextDecoder().decode(await subtle.decrypt('RSA-OAEP', browserKey.privateKey, fromBase64Url(encryptedCode)))
      if (controller.signal.aborted) {
        cancelRefresh(launched.id)
        return
      }
      if (!/^[2-9A-HJ-NP-Z]{4}$/.test(code)) throw new Error('The Arcana Guardian terminal returned an invalid matching code.')
      setMatchingCode(code)
      setRefresh(launched)
    } catch (problem) {
      if (!controller.signal.aborted) {
        if (active.current) cancelRefresh(active.current)
        active.current = null
        setError(problem)
      }
    } finally {
      if (starting.current === controller) starting.current = null
    }
  }

  const status = useQuery({
    queryKey: ['provider-value-refresh', refresh?.id],
    queryFn: ({ signal }) => api.get('/api/v1/provider-value-refreshes/{id}', { path: { id: refresh!.id }, signal }),
    initialData: refresh ?? undefined,
    enabled: open && refresh?.state === 'waiting',
    refetchInterval: ({ state }) => state.data?.state === 'waiting' && state.status !== 'error' ? 750 : false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    gcTime: 0,
    retry: false,
  })
  const current = status.data
  const ready = current?.state === 'ready' && !status.isError

  function approve() {
    if (!current || !ready) return
    active.current = null
    setOpen(false)
    setRefresh(null)
    setMatchingCode('')
    startOperation({
      key: 'provider-refresh-values',
      title: 'Approve refreshed values',
      confirmLabel: 'Save refreshed values',
      about: [['Provider', current.providerName], ['Account', current.account], ['Requested by', current.requestedBy]],
      onClose: () => cancelRefresh(current.id),
      autoPrepare: true,
      prepare: () => ({
        operation: 'provider-refresh-values',
        parameters: { id: current.id },
        summary: `Save the encrypted refresh for ${current.mappings.length} mounted fields.`,
        done: 'Refreshed values saved.',
      }),
    })
  }

  function close() {
    cancel()
    setOpen(false)
    setRefresh(null)
    setMatchingCode('')
  }

  return <>
    <Button variant="secondary" aria-label={`Refresh values for ${provider.name}`} onClick={() => void launch()}>Refresh values</Button>
    {open ? (
      <Dialog title="Refresh LastPass values" onCancel={close} step={current?.state} footer={<>
        <Button variant="secondary" onClick={close}>Cancel</Button>
        {ready ? <Button onClick={approve}>Review and approve</Button> : null}
      </>}>
        {error || status.isError ? <ProblemAlert error={error ?? status.error} />
          : current ? <>
            <Facts items={[['Requested by', current.requestedBy], ['Provider', `${current.providerName} (${current.region})`], ['Account', current.account]]} />
            <p>Matching code <code className={styles.matchingCode}>{matchingCode}</code></p>
            <ul className={styles.entries}>
              {current.mappings.map((mapping) => <li key={mapping.localName}>{formatPath(mapping.providerPath)} → <code>{mapping.localName}</code></li>)}
            </ul>
            {current.state === 'waiting' ? <p>Compare the code and request details in the Arcana Guardian terminal before entering your LastPass password there.</p> : null}
            {ready ? <Notice kind="ok">The selected values are encrypted and ready for passkey approval.</Notice> : null}
            {current.state === 'stopped' ? <Notice kind="warning">The terminal ended before returning the selected values. Open a new refresh to try again.</Notice> : null}
          </> : <Loading what="the Arcana Guardian terminal" />}
      </Dialog>
    ) : null}
  </>
}
