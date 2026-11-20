/**
 * The browser side of a run approval: the challenge the passkey signs, and the passkey's PRF output sealed to the service's key for this one request.
 * The same scheme as the passkey pages the command line opens (a fresh ECDH P-256 key, HKDF-SHA-256 with the bind as salt and "with-secrets/v1 prf" as info, AES-256-GCM with the bind as associated data),
 * so the service opens it with the code it already has. The PRF output never leaves this page unsealed.
 */

const encoder = new TextEncoder()

export function fromBase64Url(text: string): Uint8Array<ArrayBuffer> {
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4)
  const raw = atob(base64)
  const bytes = new Uint8Array(new ArrayBuffer(raw.length))
  for (let index = 0; index < raw.length; index++) bytes[index] = raw.charCodeAt(index)

  return bytes
}

export function toBase64Url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  let raw = ''
  for (const byte of bytes) raw += String.fromCharCode(byte)

  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** What the passkey signs for a decision: SHA-256 of the request's bind followed by "reuse=" and the minutes the decision lasts (0: approve once). */
export async function approveOnceChallenge(bind: Uint8Array, minutes = 0): Promise<Uint8Array<ArrayBuffer>> {
  const tail = encoder.encode('reuse=' + String(minutes))
  const joined = new Uint8Array(bind.length + tail.length)
  joined.set(bind, 0)
  joined.set(tail, bind.length)

  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', joined))
}

/** The 32 bytes the passkey derived, or null when the passkey did not return them. */
export function prfOutput(credential: PublicKeyCredential): Uint8Array<ArrayBuffer> | null {
  const first = credential.getClientExtensionResults?.().prf?.results?.first
  if (!first) return null
  const bytes = new Uint8Array(first as ArrayBuffer)

  return bytes.length === 32 ? new Uint8Array(bytes) : null
}

export type SealedPrf = { epk: string; iv: string; ct: string }

const PRF_INFO = 'with-secrets/v1 prf'
const SECRETS_INFO = 'with-secrets/v1 secrets'

/** Seals bytes to the service's key for one request (ECDH P-256, HKDF-SHA-256 with the bind as salt, AES-GCM with the bind as associated data), as the service opens them. */
async function sealBytes(plain: Uint8Array<ArrayBuffer>, bind: Uint8Array<ArrayBuffer>, serverKey: Uint8Array<ArrayBuffer>, info: string): Promise<SealedPrf & { sealed: Uint8Array<ArrayBuffer> }> {
  const subtle = globalThis.crypto.subtle
  const curve = { name: 'ECDH', namedCurve: 'P-256' }
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const mine = await subtle.generateKey(curve, false, ['deriveBits'])
  const server = await subtle.importKey('raw', serverKey, curve, false, [])
  const shared = await subtle.deriveBits({ name: 'ECDH', public: server }, mine.privateKey, 256)
  const material = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
  const key = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: bind, info: encoder.encode(info) }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
  const sealed = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: bind, tagLength: 128 }, key, plain))
  const epk = await subtle.exportKey('raw', mine.publicKey)

  return { epk: toBase64Url(epk), iv: toBase64Url(iv), ct: toBase64Url(sealed), sealed }
}

export async function sealPrf(output: Uint8Array<ArrayBuffer>, bind: Uint8Array<ArrayBuffer>, serverKey: Uint8Array<ArrayBuffer>): Promise<SealedPrf> {
  const { epk, iv, ct } = await sealBytes(output, bind, serverKey, PRF_INFO)

  return { epk, iv, ct }
}

/** The typed secret values (name to value) sealed to the service's key for one entry. Also returns the sealed bytes, whose hash the passkey signs. */
export async function sealSecrets(values: Record<string, string>, bind: Uint8Array<ArrayBuffer>, serverKey: Uint8Array<ArrayBuffer>): Promise<SealedPrf & { sealed: Uint8Array<ArrayBuffer> }> {
  return sealBytes(encoder.encode(JSON.stringify(values)), bind, serverKey, SECRETS_INFO)
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array<ArrayBuffer>> {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const joined = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    joined.set(part, offset)
    offset += part.length
  }

  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', joined))
}

/** What the passkey signs to store sealed values: SHA-256(bind || SHA-256(sealed) || SHA-256(next state)). */
export async function storeChallenge(bind: Uint8Array<ArrayBuffer>, sealed: Uint8Array<ArrayBuffer>, manifest: string): Promise<Uint8Array<ArrayBuffer>> {
  return sha256(bind, await sha256(sealed), await sha256(encoder.encode(manifest)))
}

/** What the passkey signs to remove secrets: SHA-256(bind || SHA-256(next state)). */
export async function removeChallenge(bind: Uint8Array<ArrayBuffer>, manifest: string): Promise<Uint8Array<ArrayBuffer>> {
  return sha256(bind, await sha256(encoder.encode(manifest)))
}
