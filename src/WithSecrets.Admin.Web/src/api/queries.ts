import { QueryCache, QueryClient, useQuery } from '@tanstack/react-query'
import { ApiError, api, setSessionSecret } from './client'
import type { paths } from './schema'

export const keys = {
  status: ['status'] as const,
  session: ['session'] as const,
  machines: ['machines'] as const,
  grants: ['grants'] as const,
  settings: ['settings'] as const,
  passkeys: ['passkeys'] as const,
  auditEvents: (filters: AuditFilters) => ['audit', 'events', filters] as const,
  auditChanges: (filters: AuditFilters) => ['audit', 'changes', filters] as const,
  auditGaps: (machine: string) => ['audit', 'gaps', machine] as const,
}

type EventQuery = NonNullable<paths['/api/v1/audit/events']['get']['parameters']['query']>

export type AuditFilters = Partial<Record<'machine' | 'since' | 'until' | 'type' | 'outcome' | 'grant' | 'folder' | 'text' | 'last', string>>

/** One place for server state: a 401 anywhere means the session ended, so the session is read again (the shell then shows the sign-in). */
export function createQueryClient(): QueryClient {
  const queryCache = new QueryCache({
    onError: (error, query) => {
      if (error instanceof ApiError && error.status === 401 && query.queryKey[0] !== 'session') {
        void client.invalidateQueries({ queryKey: keys.session })
      }
    },
  })
  const client: QueryClient = new QueryClient({
    queryCache,
    defaultOptions: {
      queries: {
        staleTime: 5_000,
        retry: (count, error) => !(error instanceof ApiError && error.status >= 400 && error.status < 500) && count < 1,
        refetchOnWindowFocus: true,
      },
    },
  })

  return client
}

export function useStatus() {
  return useQuery({ queryKey: keys.status, queryFn: () => api.get('/api/v1/status'), refetchInterval: 10_000 })
}

export function useSession() {
  return useQuery({
    queryKey: keys.session,
    queryFn: async () => {
      const session = await api.get('/api/v1/session')
      if (session.authenticated) return session
      setSessionSecret(null)
      if (session.login?.state === 'ready') {
        // The tap was verified: this browser claims its session (a POST). The answer carries the session's secret, once.
        const claimed = await api.post('/api/v1/session/claim', { body: {} })
        setSessionSecret(claimed.antiForgery)

        return claimed.session
      }

      return session
    },
    // While a sign-in waits for its tap the session resource is asked again (once the tap is verified the login is ready and the page claims the session).
    refetchInterval: (query) => (query.state.data?.login?.state === 'waiting' ? 1_000 : query.state.data?.authenticated ? 30_000 : false),
  })
}

export function useMachines(enabled: boolean) {
  return useQuery({ queryKey: keys.machines, queryFn: async () => (await api.get('/api/v1/machines')).items, enabled })
}

export function useGrants(enabled: boolean) {
  return useQuery({ queryKey: keys.grants, queryFn: async () => (await api.get('/api/v1/grants')).items, enabled })
}

export function useSettings(enabled: boolean) {
  return useQuery({ queryKey: keys.settings, queryFn: () => api.get('/api/v1/settings'), enabled })
}

export function usePasskeys(enabled: boolean) {
  return useQuery({ queryKey: keys.passkeys, queryFn: () => api.get('/api/v1/passkeys'), enabled })
}

export function useAuditEvents(filters: AuditFilters, enabled: boolean) {
  return useQuery({ queryKey: keys.auditEvents(filters), queryFn: async () => (await api.get('/api/v1/audit/events', { query: filters as EventQuery })).items, enabled })
}

export function useAuditChanges(filters: AuditFilters, enabled: boolean) {
  return useQuery({ queryKey: keys.auditChanges(filters), queryFn: async () => (await api.get('/api/v1/audit/changes', { query: filters as EventQuery })).items, enabled })
}

export function useAuditGaps(machine: string, enabled: boolean) {
  return useQuery({ queryKey: keys.auditGaps(machine), queryFn: async () => (await api.get('/api/v1/audit/gaps', { query: { machine } })).items, enabled })
}
