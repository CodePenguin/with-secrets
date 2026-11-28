import { useState, type ReactNode } from 'react'
import { QueryClientProvider, type QueryClient } from '@tanstack/react-query'
import { BrowserRouter, MemoryRouter } from 'react-router-dom'
import { createQueryClient } from './api/queries'
import { AnnouncerProvider } from './components/Feedback'
import { OperationProvider } from './features/authorization/OperationProvider'
import { PollContext } from './features/authorization/poll'

type Props = { children: ReactNode; client?: QueryClient; pollMs?: number; route?: string }

/** Everything the application needs above its views. The router is the browser's (base /admin) unless a test gives a route. */
export function Providers({ children, client, pollMs = 1000, route }: Props) {
  const [queryClient] = useState(() => client ?? createQueryClient())
  const router = (content: ReactNode) => (route ? <MemoryRouter initialEntries={[route]}>{content}</MemoryRouter> : <BrowserRouter basename="/admin">{content}</BrowserRouter>)

  return (
    <QueryClientProvider client={queryClient}>
      <PollContext.Provider value={pollMs}>
        <AnnouncerProvider>{router(<OperationProvider>{children}</OperationProvider>)}</AnnouncerProvider>
      </PollContext.Provider>
    </QueryClientProvider>
  )
}
