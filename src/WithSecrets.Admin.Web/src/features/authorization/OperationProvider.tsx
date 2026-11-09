import { createContext, useContext, useState, type ReactNode } from 'react'
import { OperationDialog } from './OperationDialog'
import type { OperationDef } from './operations'

const OperationContext = createContext<(def: OperationDef) => void>(() => undefined)

/** Pages ask for a change with start(def); the one dialog lives here, above the pages, so it survives navigation and re-renders. */
export function OperationProvider({ children }: { children: ReactNode }) {
  const [active, setActive] = useState<{ def: OperationDef; id: number } | null>(null)

  return (
    <OperationContext.Provider value={(def) => setActive({ def, id: Date.now() })}>
      {children}
      {active ? <OperationDialog key={active.id} def={active.def} onClose={() => setActive(null)} /> : null}
    </OperationContext.Provider>
  )
}

export function useStartOperation(): (def: OperationDef) => void {
  return useContext(OperationContext)
}
