import { describe, expect, it } from 'vitest'
import { ApiError, api, setAntiForgery } from './client'
import { installFakeApi, problem } from '../test/fakeApi'

describe('api client', () => {
  it('sends the anti-forgery value only on requests that are not a GET, and never stores it in the browser', async () => {
    const fake = installFakeApi({ 'GET /api/v1/status': { body: {} }, 'POST /api/v1/lock': { body: { operation: 'lock', outcome: 'applied', link: null } } })
    setAntiForgery('csrf-abc')
    await api.get('/api/v1/status')
    await api.post('/api/v1/lock', { body: { authorization: 'AAAAAAAA' } })

    expect(fake.calls[0]?.headers['X-Admin-Token']).toBeUndefined()
    expect(fake.calls[1]?.headers['X-Admin-Token']).toBe('csrf-abc')
    expect(fake.calls[1]?.body).toEqual({ authorization: 'AAAAAAAA' })
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
  })

  it('stays on the same origin with its cookies and no referrer', async () => {
    installFakeApi({ 'GET /api/v1/status': { body: {} } })
    await api.get('/api/v1/status')
    const [url, init] = (fetch as unknown as { mock: { calls: [string, RequestInit][] } }).mock.calls[0]!

    expect(url).toBe('/api/v1/status')
    expect(init.credentials).toBe('same-origin')
    expect(init.referrerPolicy).toBe('no-referrer')
  })

  it('fills the path and the query, and leaves empty filters out', async () => {
    const fake = installFakeApi({ 'GET /api/v1/machines/ab%2F12': { body: {} }, 'GET /api/v1/audit/events': { body: { items: [] } } })
    await api.get('/api/v1/audit/events', { query: { text: 'deploy', machine: '' } })

    expect(fake.calls[0]?.query.get('text')).toBe('deploy')
    expect(fake.calls[0]?.query.has('machine')).toBe(false)
  })

  it('turns a problem document into an error that carries only its safe sentence and code', async () => {
    installFakeApi({ 'GET /api/v1/machines': problem(401, 'session-required', 'this needs an administrator session') })
    const error = (await api.get('/api/v1/machines').catch((caught: unknown) => caught)) as ApiError

    expect(error).toBeInstanceOf(ApiError)
    expect(error.status).toBe(401)
    expect(error.code).toBe('session-required')
    expect(error.message).toBe('this needs an administrator session')
  })

  it('shortens a very long detail and reports a network failure as status 0', async () => {
    installFakeApi({ 'GET /api/v1/machines': problem(500, 'internal-error', 'x'.repeat(5000)) })
    const long = (await api.get('/api/v1/machines').catch((caught: unknown) => caught)) as ApiError
    expect(long.message.length).toBeLessThan(500)

    const failing = Object.assign(() => Promise.reject(new TypeError('failed')), {})
    globalThis.fetch = failing as unknown as typeof fetch
    const network = (await api.get('/api/v1/machines').catch((caught: unknown) => caught)) as ApiError
    expect(network.status).toBe(0)
    expect(network.code).toBe('network')
  })
})
