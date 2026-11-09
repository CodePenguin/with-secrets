import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import { ApiError } from '../api/client'
import styles from './Feedback.module.css'

type Announce = (message: string) => void

const AnnouncerContext = createContext<Announce>(() => undefined)

/** One polite live region for the whole application: async status changes (loaded, saved, refused) are announced here, not by moving focus. */
export function AnnouncerProvider({ children }: { children: ReactNode }) {
  const [message, setMessage] = useState('')
  const announce = useCallback<Announce>((text) => {
    // Cleared first so the same sentence twice is read twice.
    setMessage('')
    setTimeout(() => setMessage(text), 50)
  }, [])
  const value = useMemo(() => announce, [announce])

  return (
    <AnnouncerContext.Provider value={value}>
      {children}
      <div role="status" aria-live="polite" aria-atomic="true" className="visually-hidden">
        {message}
      </div>
    </AnnouncerContext.Provider>
  )
}

export function useAnnounce(): Announce {
  return useContext(AnnouncerContext)
}

/** A refusal or failure, shown as plain text (never as markup): the problem's title, its one safe sentence and its code. */
export function ProblemAlert({ error, title }: { error: unknown; title?: string }) {
  const api = error instanceof ApiError ? error : null
  const heading = title ?? api?.title ?? 'Something went wrong'
  const detail = api ? api.message : 'The page could not finish this. Nothing was changed that this page can tell.'

  return (
    <div role="alert" className={[styles.alert, styles.alertError].join(' ')}>
      <p className={styles.alertTitle}>
        <span aria-hidden="true">Problem: </span>
        {heading}
      </p>
      <p className={styles.alertText}>{detail}</p>
      {api && api.code !== 'error' ? (
        <p className={styles.alertCode}>
          Code: <code>{api.code}</code>
          {api.status > 0 ? ` (HTTP ${api.status})` : ''}
        </p>
      ) : null}
    </div>
  )
}

export function Notice({ kind = 'info', title, children }: { kind?: 'info' | 'warning' | 'ok'; title?: string; children: ReactNode }) {
  const prefix = kind === 'warning' ? 'Warning: ' : kind === 'ok' ? 'Done: ' : 'Note: '

  return (
    <div className={[styles.alert, kind === 'warning' ? styles.alertWarn : kind === 'ok' ? styles.alertOk : styles.alertInfo].join(' ')}>
      {title ? (
        <p className={styles.alertTitle}>
          <span aria-hidden="true">{prefix}</span>
          {title}
        </p>
      ) : null}
      <div className={styles.alertText}>{children}</div>
    </div>
  )
}

export function Loading({ what }: { what: string }) {
  return (
    <p className={styles.loading} role="status">
      Loading {what}...
    </p>
  )
}
