import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, setSessionSecret } from '../../api/client'
import { keys, useSession, useStatus } from '../../api/queries'
import { Badge } from '../../components/Card'
import { Button } from '../../components/Button'
import { Time } from '../../lib/format'
import { Gate } from '../session/Gate'
import styles from './Shell.module.css'

const links = [
  { to: '/', label: 'Overview', end: true },
  { to: '/machines', label: 'Machines', end: false },
  { to: '/grants', label: 'Grants', end: false },
  { to: '/audit', label: 'Audit', end: false },
  { to: '/settings', label: 'Settings', end: false },
  { to: '/passkeys', label: 'Passkeys', end: false },
]

/** After a navigation, focus moves to the new view's main heading (the document title changes too), so keyboard and screen reader users start at the top of it. */
function useFocusHeadingOnNavigation(main: React.RefObject<HTMLElement | null>) {
  const location = useLocation()
  const first = useRef(true)
  useEffect(() => {
    if (first.current) {
      first.current = false

      return
    }
    const heading = main.current?.querySelector<HTMLElement>('h1')
    if (heading) {
      heading.tabIndex = -1
      heading.focus()
    }
  }, [location.pathname, main])
}

export function Shell() {
  const main = useRef<HTMLElement>(null)
  const menuButton = useRef<HTMLButtonElement>(null)
  const location = useLocation()
  const [navigationOpen, setNavigationOpen] = useState(false)
  useFocusHeadingOnNavigation(main)
  const status = useStatus()
  const session = useSession()
  const queryClient = useQueryClient()
  const signOut = useMutation({
    mutationFn: () => api.delete('/api/v1/session', { body: undefined }),
    onSettled: () => {
      setSessionSecret(null)
      queryClient.clear()
      void queryClient.invalidateQueries({ queryKey: keys.session })
    },
  })
  const signedIn = session.data?.authenticated === true
  const backend = status.data?.version

  useEffect(() => {
    setNavigationOpen(false)
  }, [location.pathname])

  useEffect(() => {
    if (!navigationOpen) return

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setNavigationOpen(false)
        menuButton.current?.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [navigationOpen])

  return (
    <div className={styles.shell}>
      <a href="#main" className={styles.skip}>
        Skip to the main content
      </a>
      <header className={styles.header}>
        <p className={styles.brand}>with-secrets administration</p>
        <div className={styles.headerStatus}>
          {status.data ? status.data.locked ? <Badge tone="warn">Authority locked</Badge> : <Badge tone="ok">Authority unlocked</Badge> : null}
          {signedIn ? (
            <>
              <span className={styles.who}>
                Signed in{session.data?.admin ? <> as {session.data.admin}</> : null}
                {session.data?.idleExpires ? (
                  <>
                    , idle until <Time value={session.data.idleExpires} />
                  </>
                ) : null}
              </span>
              <Button variant="secondary" onClick={() => signOut.mutate()} disabled={signOut.isPending}>
                Sign out
              </Button>
            </>
          ) : null}
        </div>
      </header>
      <nav id="main-navigation" aria-label="Main" className={styles.nav} data-open={navigationOpen}>
        <button
          ref={menuButton}
          type="button"
          className={styles.navToggle}
          aria-expanded={navigationOpen}
          aria-controls="main-navigation-links"
          onClick={() => setNavigationOpen((open) => !open)}
        >
          Menu
        </button>
        <ul id="main-navigation-links">
          {links.map((link) => (
            <li key={link.to}>
              <NavLink
                to={link.to}
                end={link.end}
                className={({ isActive }) => (isActive ? styles.active : undefined)}
                onClick={() => setNavigationOpen(false)}
              >
                {link.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
      <main id="main" ref={main} className={styles.main}>
        <Gate>
          <Outlet />
        </Gate>
      </main>
      <footer className={styles.footer}>
        <small>
          Page version {__APP_VERSION__}
          {backend ? `, service version ${backend}` : ''}. Secret values are never shown here.
        </small>
      </footer>
    </div>
  )
}
