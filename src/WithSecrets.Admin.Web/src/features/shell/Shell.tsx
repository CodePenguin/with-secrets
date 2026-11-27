import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, setSessionSecret } from '../../api/client'
import { keys, useApprovals, useSession, useStatus } from '../../api/queries'
import { Flash } from '../../components/Flash'
import { Badge } from '../../components/Card'
import { Button } from '../../components/Button'
import { Logo } from '../../components/Logo'
import { usePollInterval } from '../authorization/poll'
import { Gate } from '../session/Gate'
import styles from './Shell.module.css'

const links = [
  { to: '/', label: 'Overview', end: true },
  { to: '/access', label: 'Access', end: false },
  { to: '/secrets', label: 'Secrets', end: false },
  { to: '/providers', label: 'Providers', end: false },
  { to: '/machines', label: 'Machines', end: false },
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
  const [openNavigationPath, setOpenNavigationPath] = useState<string | null>(null)
  const navigationOpen = openNavigationPath === location.pathname
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
  const canRead = session.data?.capabilities.includes('admin.read') === true
  const approvals = useApprovals(signedIn && status.data?.locked !== true, usePollInterval() * 3)
  const waiting = approvals.data?.items.length ?? 0

  useEffect(() => {
    if (!navigationOpen) return

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setOpenNavigationPath(null)
        menuButton.current?.focus()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [navigationOpen])

  return (
    <div className={[styles.shell, signedIn ? '' : styles.bare].join(' ')}>
      <a href="#main" className={styles.skip}>
        Skip to the main content
      </a>
      <header className={styles.header}>
        {/* The sign-in page shows the name itself, large; the header repeats it only once signed in. */}
        {signedIn ? <p className={styles.brand}><Logo className={styles.logo} /></p> : <span />}
        <div className={styles.headerStatus}>
          {status.data?.remote ? <Badge tone="neutral">Remote host</Badge> : null}
          {status.data && !status.data.remote ? status.data.locked ? <Badge tone="warn">Authority locked</Badge> : <Badge tone="ok">Authority unlocked</Badge> : null}
          {signedIn ? (
            <>
              <span className={styles.who}>
                Signed in{session.data?.admin ? <> with the passkey “{session.data.admin}”</> : null}
              </span>
              <Button variant="secondary" onClick={() => signOut.mutate()} disabled={signOut.isPending}>
                Sign out
              </Button>
            </>
          ) : null}
        </div>
      </header>
      {signedIn ? (
        <nav id="main-navigation" aria-label="Main" className={styles.nav} data-open={navigationOpen}>
          <button
            ref={menuButton}
            type="button"
            className={styles.navToggle}
            aria-expanded={navigationOpen}
            aria-controls="main-navigation-links"
            onClick={() => setOpenNavigationPath((open) => (open === location.pathname ? null : location.pathname))}
          >
            Menu
          </button>
          <ul id="main-navigation-links">
            {links.filter((link) => link.to === '/' || link.to === '/access' || (canRead && (link.to !== '/providers' || status.data?.capabilities?.providers))).map((link) => (
              <li key={link.to}>
                <NavLink
                  to={link.to}
                  end={link.end}
                  className={({ isActive }) => (isActive ? styles.active : undefined)}
                  onClick={() => setOpenNavigationPath(null)}
                >
                  {link.label}{link.to === '/access' && waiting > 0 ? <span className={styles.navBadge} aria-hidden="true"><Badge tone="warn">{waiting}</Badge></span> : null}
                </NavLink>
              </li>
            ))}
          </ul>
          {status.data?.version ? <p className={styles.version}>Version {status.data.version}</p> : null}
        </nav>
      ) : null}
      {signedIn ? <span className="visually-hidden" role="status">{waiting > 0 ? waiting + (waiting === 1 ? ' pending approval' : ' pending approvals') : ''}</span> : null}
      <main id="main" ref={main} className={styles.main}>
        <div className={styles.flash}><Flash key={location.pathname} /></div>
        <Gate>
          <Outlet />
        </Gate>
      </main>
    </div>
  )
}
