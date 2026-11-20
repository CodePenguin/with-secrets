import { ApiError } from '../api/client'
import { fromBase64Url, toBase64Url } from './passkey'

export type Started = { payload: unknown }

/** Backing out of the passkey prompt: not a failure, so the page says so quietly instead of showing a problem. */
export function promptCancelled(error: unknown): boolean {
  return error instanceof DOMException && ['AbortError', 'NotAllowedError', 'Canceled'].includes(error.name)
}

export function failure(error: unknown): unknown {
  if (error instanceof ApiError) return error

  return new ApiError(0, 'passkey-failed', 'Passkey not used', 'The passkey could not be used. Nothing was changed.')
}

/** One admin passkey assertion over `challenge`, for the request the service started. */
export async function assert(started: Started, challenge: (bind: Uint8Array<ArrayBuffer>) => Promise<Uint8Array<ArrayBuffer>>) {
  const payload = started.payload as { bind?: unknown; rpId?: unknown; timeout?: unknown }
  if (typeof payload.bind !== 'string' || typeof payload.rpId !== 'string' || typeof payload.timeout !== 'number') {
    throw new ApiError(0, 'challenge-invalid', 'Passkey unavailable', 'The service did not prepare a usable passkey challenge. Nothing was changed.')
  }
  const options: PublicKeyCredentialRequestOptions = { challenge: await challenge(fromBase64Url(payload.bind)), rpId: payload.rpId, timeout: payload.timeout, userVerification: 'required' }
  const credential = (await navigator.credentials.get({ publicKey: options })) as PublicKeyCredential | null
  if (credential === null) throw new DOMException('cancelled', 'NotAllowedError')
  const response = credential.response as AuthenticatorAssertionResponse

  return { id: toBase64Url(credential.rawId), authenticatorData: toBase64Url(response.authenticatorData), clientDataJSON: toBase64Url(response.clientDataJSON), signature: toBase64Url(response.signature) }
}
