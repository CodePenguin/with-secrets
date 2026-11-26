import { useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { api } from '../../api/client'
import { useSession } from '../../api/queries'
import { Button } from '../../components/Button'
import { Empty, PageHeader } from '../../components/Card'
import { Loading, Notice, ProblemAlert, useAnnounce } from '../../components/Feedback'
import list from '../../components/List.module.css'
import { fromBase64Url, removeChallenge, sealSecrets, storeChallenge } from '../../lib/passkey'
import { assert, failure, promptCancelled } from '../../lib/manifestProof'
import { usePageTitle } from '../../lib/usePageTitle'

const secretsKey = ['secrets'] as const

/** The stored secrets by name, with Save (also replaces) and Remove. Values are typed here, sealed in the browser and never shown again. */
export function SecretsPage() {
  usePageTitle('Secrets')
  const announce = useAnnounce()
  const queryClient = useQueryClient()
  const session = useSession()
  const canChange = session.data?.capabilities.includes('admin.decide') === true
  const secrets = useQuery({ queryKey: secretsKey, queryFn: () => api.get('/api/v1/secrets') })
  const [search] = useSearchParams()
  const [name, setName] = useState(search.get('name') ?? '')
  const [value, setValue] = useState('')
  const [problem, setProblem] = useState<unknown>(null)
  const [done, setDone] = useState<string | null>(null)
  const [cancelled, setCancelled] = useState(false)
  const [busy, setBusy] = useState(false)
  const working = useRef(false)

  async function run(work: () => Promise<string>) {
    if (working.current) return
    working.current = true
    setBusy(true)
    setProblem(null)
    setCancelled(false)
    setDone(null)
    try {
      const message = await work()
      setDone(message)
      announce(message)
    } catch (error) {
      if (promptCancelled(error)) setCancelled(true)
      else setProblem(failure(error))
    } finally {
      working.current = false
      setBusy(false)
      await queryClient.invalidateQueries({ queryKey: secretsKey })
    }
  }

  async function save() {
    const entered = name.trim()
    await run(async () => {
      const started = await api.post('/api/v1/secrets/entries', { body: { names: [entered] } })
      try {
        const bind = fromBase64Url((started.payload as { bind: string }).bind)
        const sealed = await sealSecrets({ [entered]: value }, bind, fromBase64Url(started.publicKey))
        const reply = await api.post('/api/v1/secrets/entries/{id}/seal', { path: { id: started.id }, body: { epk: sealed.epk, iv: sealed.iv, ct: sealed.ct } })
        const proof = await assert(started, (b) => storeChallenge(b, sealed.sealed, reply.manifest))
        await api.post('/api/v1/secrets/entries/{id}/save', { path: { id: started.id }, body: { epk: sealed.epk, iv: sealed.iv, ct: sealed.ct, ...proof } })
      } catch (error) {
        await api.delete('/api/v1/secrets/entries/{id}', { path: { id: started.id } }).catch(() => undefined)
        throw error
      }
      setName('')
      setValue('')

      return 'Saved ' + entered + '.'
    })
  }

  async function remove(target: string) {
    await run(async () => {
      const started = await api.post('/api/v1/secrets/removals', { body: { names: [target] } })
      try {
        const proof = await assert(started, (b) => removeChallenge(b, started.manifest))
        await api.post('/api/v1/secrets/removals/{id}/save', { path: { id: started.id }, body: { proof } })
      } catch (error) {
        await api.delete('/api/v1/secrets/entries/{id}', { path: { id: started.id } }).catch(() => undefined)
        throw error
      }

      return 'Removed ' + target + '.'
    })
  }

  const names = secrets.data?.items ?? []
  const replacing = names.includes(name.trim())

  return (
    <>
      <PageHeader title="Secrets" />
      {canChange ? <form
        onSubmit={(event) => {
          event.preventDefault()
          void save()
        }}
      >
        <p>
          <label htmlFor="secret-name">Name</label>
          <br />
          <input id="secret-name" value={name} onChange={(event) => setName(event.target.value)} autoComplete="off" spellCheck={false} maxLength={80} />
        </p>
        <p>
          <label htmlFor="secret-value">Value</label>
          <br />
          <input id="secret-value" type="password" value={value} onChange={(event) => setValue(event.target.value)} autoComplete="off" spellCheck={false} />
        </p>
        <p>
          <Button variant="primary" type="submit" disabled={busy || name.trim() === '' || value === ''}>
            {replacing ? 'Replace secret' : 'Save secret'}
          </Button>
        </p>
      </form> : null}
      {done ? <Notice kind="ok">{done}</Notice> : null}
      {problem ? <ProblemAlert error={problem} title="Nothing was changed" /> : null}
      {cancelled ? <p role="status">Passkey prompt cancelled. Nothing was changed.</p> : null}

      <h2 id="stored-secrets">Stored secrets</h2>
      {secrets.isPending ? <Loading what="secrets" /> : null}
      {secrets.isError ? <ProblemAlert error={secrets.error} title="The secrets could not be listed" /> : null}
      {secrets.data && names.length === 0 ? <Empty>No secret is stored.</Empty> : null}
      {names.length > 0 ? (
        <ul className={list.list} aria-labelledby="stored-secrets">
          {names.map((stored) => (
            <li key={stored} className={list.item}>
              <div className={list.itemHeader}>
                <h3>{stored}</h3>
              </div>
              {canChange ? <div className={list.actions}>
                <Button variant="danger" disabled={busy} onClick={() => void remove(stored)}>
                  Remove <span className="visually-hidden">secret {stored}</span>
                </Button>
              </div> : null}
            </li>
          ))}
        </ul>
      ) : null}
    </>
  )
}
