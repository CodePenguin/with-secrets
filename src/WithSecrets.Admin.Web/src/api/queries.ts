import { QueryCache, QueryClient, useQuery } from '@tanstack/react-query'
import { ApiError, api, setSessionSecret } from './client'
import type { paths } from './schema'

export const keys = {
  status: ['status'] as const,
  session: ['session'] as const,
  machines: ['machines'] as const,
  invitations: ['invitations'] as const,
  grants: ['grants'] as const,
  approvals: ['approvals'] as const,
  approval: (id: string) => ['approvals', id] as const,
  settings: ['settings'] as const,
  passkeys: ['passkeys'] as const,
  providers: ['providers'] as const,
  providerTypes: ['provider-types'] as const,
  providerMounts: (id: string) => ['providers', id, 'mounts'] as const,
  mounts: ['mounts'] as const,
  mountEntries: (id: string) => ['mounts', id, 'entries'] as const,
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

/** `poll`: ask again every so many milliseconds (the Machines view does, so a machine that has just paired appears by itself). */
export function useMachines(enabled: boolean, poll: number | false = false) {
  return useQuery({ queryKey: keys.machines, queryFn: async () => (await api.get('/api/v1/machines')).items, enabled, refetchInterval: poll })
}

export function useInvitations(enabled: boolean, poll: number | false = false) {
  return useQuery({ queryKey: keys.invitations, queryFn: async () => (await api.get('/api/v1/pairing/invitations')).items, enabled, refetchInterval: poll })
}

export function useGrants(enabled: boolean, poll: number | false = false) {
  return useQuery({ queryKey: keys.grants, queryFn: async () => (await api.get('/api/v1/grants')).items, enabled, refetchInterval: poll })
}

export function useSettings(enabled: boolean) {
  return useQuery({ queryKey: keys.settings, queryFn: () => api.get('/api/v1/settings'), enabled })
}

export function usePasskeys(enabled: boolean) {
  return useQuery({ queryKey: keys.passkeys, queryFn: () => api.get('/api/v1/passkeys'), enabled })
}

export function useProviders(enabled: boolean) {
  return useQuery({ queryKey: keys.providers, queryFn: () => api.get('/api/v1/providers'), enabled, refetchInterval: 10_000 })
}

export function useProviderTypes(enabled: boolean) {
  return useQuery({ queryKey: keys.providerTypes, queryFn: () => api.get('/api/v1/providers/types'), enabled })
}

export function useMounts(id: string, enabled: boolean) {
  return useQuery({ queryKey: keys.providerMounts(id), queryFn: () => api.get('/api/v1/providers/{id}/mounts', { path: { id } }), enabled, refetchInterval: 10_000 })
}

export function mountEntriesQuery(id: string) {
  return { queryKey: keys.mountEntries(id), queryFn: () => api.get('/api/v1/mounts/{id}/entries', { path: { id } }), refetchInterval: 10_000 }
}

export function useEntries(id: string) {
  return useQuery(mountEntriesQuery(id))
}

export function useAllMounts(enabled: boolean) {
  return useQuery({ queryKey: keys.mounts, queryFn: () => api.get('/api/v1/mounts'), enabled, refetchInterval: 10_000 })
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

/** The run requests waiting for a decision. `poll`: ask again every so many milliseconds, so a request that has just arrived appears by itself. */
export function useApprovals(enabled: boolean, poll: number | false = false) {
  // Read the whole bounded queue so Access can order every waiting request by expiry.
  return useQuery({ queryKey: keys.approvals, queryFn: () => api.get('/api/v1/approvals', { query: { limit: 64 } }), enabled, refetchInterval: poll })
}

export function useApproval(id: string, poll: number | false = false) {
  return useQuery({ queryKey: keys.approval(id), queryFn: () => api.get('/api/v1/approvals/{requestId}', { path: { requestId: id } }), refetchInterval: poll })
}
