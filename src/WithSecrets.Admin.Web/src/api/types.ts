import type { components } from './schema'

type S = components['schemas']

export type Status = S['Status']
export type Session = S['Session']
export type Machine = S['Machine']
export type Grant = S['Grant']
export type AuditEvent = S['AuditEvent']
export type AuditChange = S['AuditChange']
export type AuditGap = S['AuditGap']
export type Settings = S['Settings']
export type Passkey = S['Passkey']
export type Authorization = S['Authorization']
export type AuthorizationRequest = S['AuthorizationRequest']
export type MutationResponse = S['MutationResponse']
export type OperationName = AuthorizationRequest['operation']
export type ParameterValue = string | number | boolean
