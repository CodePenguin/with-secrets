import { useId, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { ApiError, api } from '../../api/client'
import { useAllMounts, useProviders, useSession, useStatus } from '../../api/queries'
import type { Mount } from '../../api/types'
import { Button } from '../../components/Button'
import { PageHeader } from '../../components/Card'
import { Dialog } from '../../components/Dialog'
import { Field, controlClass } from '../../components/Field'
import { Loading, Notice, ProblemAlert, useAnnounce } from '../../components/Feedback'
import { Icon } from '../../components/Icon'
import { fromBase64Url, removeChallenge, sealSecrets, storeChallenge } from '../../lib/passkey'
import { assert, failure, promptCancelled } from '../../lib/manifestProof'
import { usePageTitle } from '../../lib/usePageTitle'
import { useStartOperation } from '../authorization/OperationProvider'
import { mountFromSecrets } from '../providers/providerOperations'
import { SecretFolders } from './SecretFolders'
import styles from './SecretsPage.module.css'

const secretsKey = ['secrets'] as const
const maxBatchSize = 20

type SecretDraft = { source?: string; name: string; folder: string }
type BatchEntry = { id: number; name: string; value: string }

function editDraft(path: string): SecretDraft {
  const separator = path.lastIndexOf('/')
  return { source: path, name: path.slice(separator + 1), folder: separator === -1 ? '' : path.slice(0, separator) }
}

function folderPrefixes(names: readonly string[], mounts: readonly Mount[]) {
  const folders = new Set<string>()
  for (const path of [...names, ...mounts.map(mount => mount.logicalPath + (mount.kind === 'tree' ? '/' : ''))]) {
    const parts = path.split('/')
    for (let length = 1; length < parts.length; length++) folders.add(parts.slice(0, length).join('/') + '/')
  }
  return [...folders].sort((left, right) => left.localeCompare(right))
}

/** The stored secrets by name, with Save (also replaces) and Remove. Values are typed here, sealed in the browser and never shown again. */
export function SecretsPage() {
  usePageTitle('Secrets')
  const announce = useAnnounce()
  const queryClient = useQueryClient()
  const session = useSession()
  const status = useStatus()
  const canChange = session.data?.capabilities.includes('admin.decide') === true
  const canWrite = session.data?.capabilities.includes('secrets.write') === true
  const showMounts = status.data?.capabilities?.providers === true && session.data?.capabilities.includes('admin.read') === true
  const mounts = useAllMounts(showMounts)
  const providers = useProviders(showMounts && canChange && status.data?.locked === false)
  const start = useStartOperation()
  const secrets = useQuery({ queryKey: secretsKey, queryFn: () => api.get('/api/v1/secrets') })
  const [search] = useSearchParams()
  const [prefill, setPrefill] = useState(() => search.get('name'))
  const [draft, setDraft] = useState<SecretDraft | null>(null)
  const [value, setValue] = useState('')
  const [extraEntries, setExtraEntries] = useState<BatchEntry[]>([])
  const nextEntryId = useRef(1)
  const [problem, setProblem] = useState<unknown>(null)
  const [done, setDone] = useState<string | null>(null)
  const [cancelled, setCancelled] = useState(false)
  const [busy, setBusy] = useState(false)
  const working = useRef(false)
  const formId = useId()

  const names = secrets.data?.items ?? []
  const editor = draft ?? (prefill && secrets.data
    ? names.includes(prefill) ? editDraft(prefill) : { name: prefill, folder: '' }
    : null)
  const source = editor?.source
  const name = editor?.name.trim() ?? ''
  const folder = editor?.folder.trim().replace(/\/$/, '') ?? ''
  const destination = folder ? folder + '/' + name : name
  const moving = !!source && destination !== source
  const nameError = source && name.includes('/') ? 'Enter the folder separately.' :
    moving && names.includes(destination) ? 'A secret already exists at this path.' : undefined
  const entries = [{ name: destination, value }, ...extraEntries.map(entry => ({ name: entry.name.trim(), value: entry.value }))]
  const entered = entries.map(entry => entry.name)
  const nonEmptyNames = entered.filter(Boolean)
  const duplicate = new Set(nonEmptyNames).size < nonEmptyNames.length
  const replacing = entries.some(entry => names.includes(entry.name)) && !moving
  const canSave = source
    ? !!name && !nameError && (moving ? canChange : value !== '')
    : !duplicate && entries.every(entry => entry.name && entry.value)

  function openEditor(next: SecretDraft) {
    setPrefill(null)
    setDraft(next)
    setValue('')
    setExtraEntries([])
    setProblem(null)
    setCancelled(false)
  }

  function closeEditor() {
    setPrefill(null)
    setDraft(null)
    setValue('')
    setExtraEntries([])
    setProblem(null)
    setCancelled(false)
  }

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
    if (!canSave) return
    await run(async () => {
      const started = await api.post('/api/v1/secrets/entries', { body: { names: entered, source } })
      try {
        if (!source && started.fields.some(field => field.replace !== names.includes(field.name))) {
          throw new ApiError(409, 'secret-list-changed', 'Secret list changed', 'Review which names will be replaced, then save again.')
        }
        const bind = fromBase64Url((started.payload as { bind: string }).bind)
        const values = Object.fromEntries(entries.filter(entry => entry.value !== '').map(entry => [entry.name, entry.value]))
        const sealed = await sealSecrets(values, bind, fromBase64Url(started.publicKey))
        const reply = await api.post('/api/v1/secrets/entries/{id}/seal', { path: { id: started.id }, body: { epk: sealed.epk, iv: sealed.iv, ct: sealed.ct } })
        const proof = await assert(started, (b) => storeChallenge(b, sealed.sealed, reply.manifest))
        await api.post('/api/v1/secrets/entries/{id}/save', { path: { id: started.id }, body: { epk: sealed.epk, iv: sealed.iv, ct: sealed.ct, ...proof } })
      } catch (error) {
        await api.delete('/api/v1/secrets/entries/{id}', { path: { id: started.id } }).catch(() => undefined)
        throw error
      }
      closeEditor()

      return 'Saved ' + entered.join(', ') + '.'
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

  const mountable = providers.data?.filter(provider => provider.actions.includes('add-mount')) ?? []
  const feedback = (
    <>
      {problem ? <ProblemAlert error={problem} title="Nothing was changed" /> : null}
      {cancelled ? <p role="status">Passkey prompt cancelled. Nothing was changed.</p> : null}
    </>
  )
  const showEditor = canWrite && editor !== null

  function updateEntry(id: number, changes: Partial<Pick<BatchEntry, 'name' | 'value'>>) {
    setExtraEntries(current => current.map(entry => entry.id === id ? { ...entry, ...changes } : entry))
  }

  function addEntry() {
    const id = nextEntryId.current++
    setExtraEntries(current => [...current, { id, name: '', value: '' }])
  }

  return (
    <>
      <PageHeader title="Secrets">
        {showMounts && canChange && status.data?.locked === false && mountable.length > 0 ? (
          <Button disabled={busy} aria-haspopup="dialog" onClick={() => {
            setDone(null)
            setProblem(null)
            setCancelled(false)
            start(mountFromSecrets(mountable, folderPrefixes(names, mounts.data ?? [])))
          }}><Icon name="mount" /> Mount provider</Button>
        ) : null}
        {canWrite ? (
          <Button variant="primary" disabled={busy} aria-haspopup="dialog" onClick={() => openEditor({ name: '', folder: '' })}>
            <Icon name="plus" /> Add secret
          </Button>
        ) : null}
      </PageHeader>
      {showEditor ? <Dialog
        title={source ? 'Edit secret' : 'Add secret'}
        onCancel={() => {
          if (!working.current) closeEditor()
        }}
        footer={
          <>
            <Button disabled={busy} onClick={closeEditor}>Cancel</Button>
            <Button variant="primary" type="submit" form={formId} disabled={busy || !canSave}>
              {source ? 'Save changes' : extraEntries.length > 0 ? 'Save secrets' : 'Save secret'}
            </Button>
          </>
        }
      >
        <form id={formId} className={styles.form} onSubmit={(event) => {
          event.preventDefault()
          void save()
        }}>
          <Field label="Name" hint={source ? undefined : 'Use / to add folders, for example apps/API_KEY.'} error={nameError} required>
            {control => <input {...control} className={controlClass} value={editor.name} onChange={(event) => setDraft({ ...editor, name: event.target.value })} autoComplete="off" spellCheck={false} maxLength={200} readOnly={!!source && !canChange} disabled={busy} required />}
          </Field>
          {source ? (
            <Field label="Folder path" hint="Leave blank to use the root.">
              {control => <input {...control} className={controlClass} value={editor.folder} onChange={(event) => setDraft({ ...editor, folder: event.target.value })} autoComplete="off" spellCheck={false} maxLength={200} readOnly={!canChange} disabled={busy} />}
            </Field>
          ) : null}
          <Field label={source ? 'New value' : 'Value'} hint={moving ? 'Leave blank to keep the current value.' : undefined} required={!moving}>
            {control => <input {...control} className={controlClass} type="password" value={value} onChange={(event) => setValue(event.target.value)} autoComplete="off" spellCheck={false} maxLength={4096} disabled={busy} required={!moving} />}
          </Field>
          {extraEntries.map((entry, index) => (
            <fieldset key={entry.id} className={styles.entry} disabled={busy}>
              <Field label={`Name ${index + 2}`} required>
                {control => <input {...control} className={controlClass} value={entry.name} onChange={event => updateEntry(entry.id, { name: event.target.value })} autoComplete="off" spellCheck={false} maxLength={200} required />}
              </Field>
              <Field label={`Value ${index + 2}`} required>
                {control => <input {...control} className={controlClass} type="password" value={entry.value} onChange={event => updateEntry(entry.id, { value: event.target.value })} autoComplete="off" spellCheck={false} maxLength={4096} required />}
              </Field>
              <Button type="button" onClick={() => setExtraEntries(current => current.filter(item => item.id !== entry.id))}>
                Remove entry {index + 2}
              </Button>
            </fieldset>
          ))}
          {duplicate ? <p role="status">Enter each secret name once.</p> : null}
          {replacing ? <p>Existing grants can use replacement values without asking again.</p> : null}
          {!source ? <div><Button type="button" disabled={busy || entries.length >= maxBatchSize} onClick={addEntry}>Add another secret</Button></div> : null}
        </form>
        {feedback}
      </Dialog> : null}
      <div className={styles.content}>
        {done ? <Notice kind="ok">{done}</Notice> : null}
        {showEditor ? null : feedback}
        {secrets.isPending ? <Loading what="secrets" /> : null}
        {secrets.isError ? <ProblemAlert error={secrets.error} title="The secrets could not be listed" /> : null}
        {showMounts && mounts.isPending ? <Loading what="provider mounts" /> : null}
        {mounts.isError ? <ProblemAlert error={mounts.error} title="The provider mounts could not be listed" /> : null}
        <SecretFolders
          names={names}
          mounts={showMounts ? mounts.data ?? [] : []}
          edit={canWrite ? path => openEditor(editDraft(path)) : undefined}
          remove={canChange ? path => void remove(path) : undefined}
          busy={busy}
          loading={!secrets.data || (showMounts && !mounts.data)}
        />
      </div>
    </>
  )
}
