import { useQueries } from '@tanstack/react-query'
import { useState } from 'react'
import { mountEntriesQuery } from '../../api/queries'
import type { Mount } from '../../api/types'
import { Button } from '../../components/Button'
import { Empty } from '../../components/Card'
import { Loading, ProblemAlert } from '../../components/Feedback'
import { Icon } from '../../components/Icon'
import styles from './SecretFolders.module.css'

type SecretLeaf = { name: string; path: string; manual?: boolean; detail?: string }
type Folder = {
  folders: Map<string, Folder>
  leaves: SecretLeaf[]
  mount?: { source: string; pending: boolean; error: Error | null; empty: boolean }
}

function emptyFolder(): Folder {
  return { folders: new Map(), leaves: [] }
}

function folderAt(root: Folder, parts: string[]): Folder {
  let folder = root
  for (const part of parts) {
    let child = folder.folders.get(part)
    if (!child) {
      child = emptyFolder()
      folder.folders.set(part, child)
    }
    folder = child
  }
  return folder
}

function addSecret(root: Folder, path: string, manual = false, detail?: string) {
  const parts = path.split('/')
  const name = parts.pop() ?? path
  folderAt(root, parts).leaves.push({ name, path, manual, detail })
}

// Match the authority’s source selection: an exact single mount wins, then the longest matching tree.
function sourceFor(path: string, mounts: readonly Mount[]): Mount | undefined {
  const single = mounts.find(mount => mount.kind === 'single' && mount.logicalPath === path)
  if (single) return single
  return mounts.reduce<Mount | undefined>((best, mount) =>
    mount.kind === 'tree' && path.startsWith(mount.logicalPath + '/') &&
      (!best || mount.logicalPath.length > best.logicalPath.length) ? mount : best, undefined)
}

type Actions = {
  edit?: (path: string) => void
  remove?: (path: string) => void
  busy: boolean
  expanded: ReadonlySet<string>
  expand: (path: string, open: boolean) => void
}

function FolderContents({ folder, actions, path = '' }: { folder: Folder; actions: Actions; path?: string }) {
  return (
    // eslint-disable-next-line jsx-a11y/no-redundant-roles -- Safari drops list semantics when list markers are hidden
    <ul role="list" className={path ? styles.children : styles.tree} aria-label={path ? undefined : 'Secrets'}>
      {[...folder.folders].sort(([a], [b]) => a.localeCompare(b)).map(([label, child]) => {
        const mount = child.mount
        const childPath = path ? path + '/' + label : label
        return (
          <li key={label}>
            <details className={styles.folder} open={actions.expanded.has(childPath)} onToggle={event => actions.expand(childPath, event.currentTarget.open)}>
              <summary className={styles.row}>
                <span className={styles.disclosure}><Icon name="chevron" /></span>
                <Icon name="folder" />
                <span className={styles.label}>
                  <strong>{label}</strong>
                  {mount ? <span className={styles.secondary}>{mount.source}</span> : null}
                </span>
              </summary>
              {mount?.pending ? <Loading what="mounted secrets" /> : null}
              {mount?.error ? <ProblemAlert error={mount.error} title="The mounted secrets could not be listed" /> : null}
              {mount?.empty && !child.folders.size && !child.leaves.length ? <Empty>No secret is listed in this mount.</Empty> : null}
              {child.folders.size || child.leaves.length ? <FolderContents folder={child} actions={actions} path={childPath} /> : null}
            </details>
          </li>
        )
      })}
      {folder.leaves.sort((a, b) => a.name.localeCompare(b.name)).map(entry => (
        <li className={styles.row} key={`${entry.manual ? 'manual' : 'mounted'}:${entry.path}`}>
          <span className={styles.leafIcon}><Icon name="key" /></span>
          <span className={styles.label}>
            <strong>{entry.name}</strong>
            {entry.path !== entry.name ? <code className={styles.path}>{entry.path}</code> : null}
            {entry.detail ? <span className={styles.secondary}>{entry.detail}</span> : null}
          </span>
          {entry.manual && (actions.edit || actions.remove) ? (
            <div className={styles.actions}>
              {actions.edit ? (
                <Button className={styles.iconButton} aria-label={`Edit secret ${entry.path}`} title="Edit secret" aria-haspopup="dialog"
                  disabled={actions.busy} onClick={() => actions.edit?.(entry.path)}>
                  <Icon name="edit" />
                </Button>
              ) : null}
              {actions.remove ? (
                <Button variant="dangerOutline" className={styles.iconButton} aria-label={`Remove secret ${entry.path}`} title="Remove secret"
                  disabled={actions.busy} onClick={() => actions.remove?.(entry.path)}>
                  <Icon name="trash" />
                </Button>
              ) : null}
            </div>
          ) : null}
        </li>
      ))}
    </ul>
  )
}

export function SecretFolders({ names, mounts, edit, remove, busy, loading }: {
  names: readonly string[]; mounts: readonly Mount[]; edit?: (path: string) => void; remove?: (path: string) => void; busy: boolean; loading: boolean
}) {
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(() => new Set())
  const directories = mounts.filter(mount => mount.kind === 'tree')
  const listings = useQueries({
    queries: directories.map(mount => ({ ...mountEntriesQuery(mount.id), enabled: expanded.has(mount.logicalPath) })),
  })
  const root = emptyFolder()

  for (const path of names) {
    const source = sourceFor(path, mounts)
    addSecret(root, path, true, source ? `Shadowed by ${source.instanceName}` : undefined)
  }
  for (const mount of mounts) {
    if (mount.kind === 'single')
      addSecret(root, mount.logicalPath, false, mount.entries ? mount.instanceName : `${mount.instanceName} · Unavailable`)
  }
  directories.forEach((mount, index) => {
    const listing = listings[index]!
    const paths = listing.data?.map(entry => entry.logicalPath).filter(path => sourceFor(path, mounts)?.id === mount.id)
    const folder = folderAt(root, mount.logicalPath.split('/'))
    folder.mount = { source: mount.instanceName, pending: listing.isPending, error: listing.error, empty: paths?.length === 0 }
    for (const path of paths ?? []) addSecret(root, path)
  })

  function expand(path: string, open: boolean) {
    setExpanded(current => {
      if (current.has(path) === open) return current
      const next = new Set(current)
      if (open) next.add(path)
      else next.delete(path)
      return next
    })
  }

  if (!root.folders.size && !root.leaves.length) return loading ? null : <Empty>Add a secret or a mount secret provider.</Empty>
  return <FolderContents folder={root} actions={{ edit, remove, busy, expanded, expand }} />
}
