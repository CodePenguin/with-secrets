import { createContext, useContext } from 'react'

/** How often the page asks where an authorization or a sign-in stands (tests make it short). */
export const PollContext = createContext(1000)

export function usePollInterval(): number {
  return useContext(PollContext)
}
