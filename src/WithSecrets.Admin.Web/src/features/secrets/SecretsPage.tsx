import { useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { api } from '../../api/client'
import { useAllMounts, useSession, useStatus } from '../../api/queries'
import { Button } from '../../components/Button'
import { PageHeader } from '../../components/Card'
import { Loading, Notice, ProblemAlert, useAnnounce } from '../../components/Feedback'
import { fromBase64Url, removeChallenge, sealSecrets, storeChallenge } from '../../lib/passkey'
import { assert, failure, promptCancelled } from '../../lib/manifestProof'
import { usePageTitle } from '../../lib/usePageTitle'
import { LocalSecretFolder, MountedSecretFolders } from './SecretFolders'

const secretsKey = ['secrets'] as const

/** The stored secrets by name, with Save (also replaces) and Remove. Values are typed here, sealed in the browser and never shown again. */
export function SecretsPage() {
  usePageTitle('Secrets')
  const announce = useAnnounce()
  const queryClient = useQueryClient()
  const session = useSession()
  const status = useStatus()
  const canChange = session.data?.capabilities.includes('admin.decide') === true
  const showMounts = status.data?.capabilities?.providers === true && session.data?.capabilities.includes('admin.read') === true
  const mounts = useAllMounts(showMounts)
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
          <input id="secret-name" value={name} onChange={(event) => setName(event.target.value)} autoComplete="off" spellCheck={false} maxLength={200} aria-describedby="secret-name-hint" />
          <br />
          <small id="secret-name-hint">Use / to add folders, for example apps/API_KEY.</small>
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

      <h2>Mount points</h2>
      {secrets.isPending ? <Loading what="secrets" /> : null}
      {secrets.isError ? <ProblemAlert error={secrets.error} title="The secrets could not be listed" /> : null}
      {secrets.data ? <LocalSecretFolder names={names} mounts={mounts.data ?? []} remove={canChange ? path => void remove(path) : undefined} busy={busy} /> : null}
      {showMounts && mounts.isPending ? <Loading what="provider mounts" /> : null}
      {mounts.isError ? <ProblemAlert error={mounts.error} title="The provider mounts could not be listed" /> : null}
      {mounts.data ? <MountedSecretFolders mounts={mounts.data} /> : null}
    </>
  )
}
