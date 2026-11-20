import { createContext, useContext, useState, type ReactNode } from 'react'
import { pendingAuthorization, type PendingAuthorization } from '../../api/client'
import { OperationDialog } from './OperationDialog'
import type { OperationDef } from './operations'

const OperationContext = createContext<(def: OperationDef) => void>(() => undefined)

type Active = { def?: OperationDef; resume?: PendingAuthorization; id: number }

/**
 * Pages ask for a change with start(def); the one dialog lives here, above the pages, so it survives navigation and re-renders. A page that was reloaded (or discarded and restored by the browser) while a
 * passkey tap was waiting opens the dialog again on that authorization, which then shows what became of the tap: the service makes the change when the tap is verified, whether or not this page was there.
 */
export function OperationProvider({ children }: { children: ReactNode }) {
  const [active, setActive] = useState<Active | null>(() => {
    const waiting = pendingAuthorization()

    return waiting ? { resume: waiting, id: Date.now() } : null
  })

  return (
    <OperationContext.Provider value={(def) => setActive({ def, id: Date.now() })}>
      {children}
      {active ? <OperationDialog key={active.id} def={active.def} resume={active.resume} onClose={() => setActive(null)} /> : null}
    </OperationContext.Provider>
  )
}

export function useStartOperation(): (def: OperationDef) => void {
  return useContext(OperationContext)
}
