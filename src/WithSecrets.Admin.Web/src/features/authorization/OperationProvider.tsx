import { createContext, useContext, useState, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { pendingAuthorization, type PendingAuthorization } from '../../api/client'
import { flash } from '../../components/Flash'
import { OperationDialog } from './OperationDialog'
import type { OperationDef } from './operations'

const OperationContext = createContext<(def: OperationDef) => void>(() => undefined)

type Active = { def?: OperationDef; resume?: PendingAuthorization; id: number }
const providerOperations = new Set([
  'provider-add', 'provider-config', 'provider-max-stale', 'provider-refresh-values', 'provider-remove', 'mount-add', 'mount-remove',
])

/**
 * Pages ask for a change with start(def); the one dialog lives here, above the pages, so it survives navigation and re-renders. A page that was reloaded (or discarded and restored by the browser) while a
 * passkey tap was waiting opens the dialog again on that authorization, which then shows what became of the tap: the service makes the change when the tap is verified, whether or not this page was there.
 */
export function OperationProvider({ children }: { children: ReactNode }) {
  const location = useLocation()
  const navigate = useNavigate()
  const [active, setActive] = useState<Active | null>(() => {
    const waiting = pendingAuthorization()

    return waiting ? { resume: waiting, id: Date.now() } : null
  })

  function close() {
    active?.def?.onClose?.()
    setActive(null)
  }

  function showApplied(operation: string, message: string) {
    const providerDetail = location.pathname.startsWith('/providers/') && operation !== 'provider-remove' && operation !== 'provider-add'
    const secretsMount = location.pathname === '/secrets' && operation === 'mount-add'
    const destination = providerOperations.has(operation) && !providerDetail && !secretsMount
      ? '/providers'
      : location.pathname + location.search + location.hash
    close()
    navigate(destination, { replace: destination === location.pathname + location.search + location.hash || operation === 'provider-remove', state: flash(message) })
    return true
  }

  return (
    <OperationContext.Provider value={(def) => setActive({ def, id: Date.now() })}>
      {children}
      {active ? <OperationDialog key={active.id} def={active.def} resume={active.resume} onClose={close} onApplied={showApplied} /> : null}
    </OperationContext.Provider>
  )
}

export function useStartOperation(): (def: OperationDef) => void {
  return useContext(OperationContext)
}
