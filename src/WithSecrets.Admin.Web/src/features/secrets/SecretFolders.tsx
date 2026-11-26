import { useState, type ReactNode } from 'react'
import { useEntries } from '../../api/queries'
import type { Mount } from '../../api/types'
import { Button } from '../../components/Button'
import { Empty } from '../../components/Card'
import { Loading, ProblemAlert } from '../../components/Feedback'
import { Icon } from '../../components/Icon'
import styles from './SecretFolders.module.css'

type SecretLeaf = { name: string; path: string; secondary?: string }
type Folder = { folders: Map<string, Folder>; leaves: SecretLeaf[] }

function emptyFolder(): Folder {
  return { folders: new Map(), leaves: [] }
}

function folderTree(paths: readonly string[], prefix = ''): Folder {
  const root = emptyFolder()
  for (const path of paths) {
    const parts = path.slice(prefix.length).split('/')
    const name = parts.pop() ?? path
    let folder = root
    for (const part of parts) {
      let child = folder.folders.get(part)
      if (!child) {
        child = emptyFolder()
        folder.folders.set(part, child)
      }
      folder = child
    }
    folder.leaves.push({ name, path })
  }
  return root
}

function FolderSummary({ label, source }: { label: string; source?: string }) {
  return <summary><Icon name="folder" /> {label}{source ? <span className={styles.secondary}>{source}</span> : null}</summary>
}

function SecretRow({ entry, action }: { entry: SecretLeaf; action?: ReactNode }) {
  return (
    <li className={styles.row}>
      <div>
        <h3><Icon name="key" /> {entry.name}</h3>
        {entry.path !== entry.name ? <code className={styles.path}>{entry.path}</code> : null}
        {entry.secondary ? <span className={styles.secondary}>{entry.secondary}</span> : null}
      </div>
      {action}
    </li>
  )
}

function FolderContents({ folder, leaf }: { folder: Folder; leaf: (entry: SecretLeaf) => ReactNode }) {
  return (
    <ul className={styles.children}>
      {[...folder.folders].sort(([a], [b]) => a.localeCompare(b)).map(([label, child]) => (
        <li key={label}>
          <details className={styles.folder}>
            <FolderSummary label={label} />
            <FolderContents folder={child} leaf={leaf} />
          </details>
        </li>
      ))}
      {folder.leaves.map(leaf)}
    </ul>
  )
}

// Match the authority's source selection: an exact single mount wins, then the longest matching tree.
function sourceFor(path: string, mounts: readonly Mount[]): Mount | undefined {
  const single = mounts.find(mount => mount.kind === 'single' && mount.logicalPath === path)
  if (single) return single
  return mounts.reduce<Mount | undefined>((best, mount) =>
    mount.kind === 'tree' && path.startsWith(mount.logicalPath + '/') &&
      (!best || mount.logicalPath.length > best.logicalPath.length) ? mount : best, undefined)
}

export function LocalSecretFolder({ names, mounts, remove, busy }: {
  names: readonly string[]; mounts: readonly Mount[]; remove?: (name: string) => void; busy: boolean
}) {
  return (
    <details className={styles.folder} open>
      <FolderSummary label="Local" source="Manually added secrets" />
      {names.length === 0 ? <Empty>No secret is stored.</Empty> : (
        <FolderContents folder={folderTree(names)} leaf={entry => {
          const source = sourceFor(entry.path, mounts)
          return <SecretRow key={entry.path} entry={{ ...entry, secondary: source ? `Shadowed by ${source.instanceName}` : undefined }} action={remove ? (
            <Button variant="danger" disabled={busy} onClick={() => remove(entry.path)}>
              Remove <span className="visually-hidden">secret {entry.path}</span>
            </Button>
          ) : null} />
        }} />
      )}
    </details>
  )
}

function MountedContents({ mount, mounts }: { mount: Mount; mounts: readonly Mount[] }) {
  const entries = useEntries(mount.id)
  if (entries.isPending) return <Loading what="mounted secrets" />
  if (entries.isError) return <ProblemAlert error={entries.error} title="The mounted secrets could not be listed" />
  const paths = entries.data.map(entry => entry.logicalPath).filter(path => sourceFor(path, mounts)?.id === mount.id)
  if (!paths.length) return <Empty>No secret is listed in this mount.</Empty>
  return <FolderContents folder={folderTree(paths, mount.logicalPath + '/')} leaf={entry => <SecretRow key={entry.path} entry={entry} />} />
}

function MountedFolder({ mount, mounts }: { mount: Mount; mounts: readonly Mount[] }) {
  const [open, setOpen] = useState(false)
  return (
    <details className={styles.folder} onToggle={event => setOpen(event.currentTarget.open)}>
      <FolderSummary label={mount.logicalPath + '/'} source={mount.instanceName} />
      {open ? <MountedContents mount={mount} mounts={mounts} /> : null}
    </details>
  )
}

export function MountedSecretFolders({ mounts }: { mounts: readonly Mount[] }) {
  if (!mounts.length) return null
  return (
    <ul className={styles.tree} aria-label="Provider mounts">
      {mounts.map(mount => mount.kind === 'tree'
        ? <li key={mount.id}><MountedFolder mount={mount} mounts={mounts} /></li>
        : <SecretRow key={mount.id} entry={{
          name: mount.logicalPath, path: mount.logicalPath,
          secondary: mount.entries ? mount.instanceName : `${mount.instanceName} · Unavailable`,
        }} />)}
    </ul>
  )
}
