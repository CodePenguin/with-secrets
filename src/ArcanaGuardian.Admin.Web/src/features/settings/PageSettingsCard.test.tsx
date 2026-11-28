import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { signedIn } from '../../test/fakeApi'
import { renderApp } from '../../test/render'

afterEach(() => {
  vi.unstubAllGlobals()
})

const current = { reuseMaxMinutes: 480, baseUrl: null, port: 0, timeoutMinutes: 5 }

describe('Approval pages settings', () => {
  it('shows the stored values and keeps Save off until something changes', async () => {
    signedIn({ 'GET /api/v1/page-settings': { body: current } })
    renderApp('/settings')
    const port = (await screen.findByLabelText(/^Port/)) as HTMLInputElement
    await waitFor(() => expect(port.value).toBe('0'))
    const save = screen.getByRole('button', { name: /^Save with a passkey/ }) as HTMLButtonElement
    expect(save.disabled).toBe(true)
    await userEvent.clear(port)
    await userEvent.type(port, '8765')
    expect(save.disabled).toBe(false)
  })

  it('cancels the pending change when the passkey is not used', async () => {
    const api = signedIn({
      'GET /api/v1/page-settings': { body: current },
      'POST /api/v1/page-settings/changes': { status: 201, body: { id: 'ch-1', manifest: 'AQ', payload: { bind: 'AQ', rpId: 'localhost', timeout: 60000 } } },
      'DELETE /api/v1/page-settings/changes/ch-1': { body: { ok: true } },
    })
    vi.stubGlobal('navigator', { ...navigator, credentials: { get: vi.fn().mockRejectedValue(new DOMException('no', 'NotAllowedError')) } })
    renderApp('/settings')
    const port = (await screen.findByLabelText(/^Port/)) as HTMLInputElement
    await waitFor(() => expect(port.value).toBe('0'))
    await userEvent.clear(port)
    await userEvent.type(port, '8765')
    await userEvent.click(screen.getByRole('button', { name: /^Save with a passkey/ }))
    expect(await screen.findByText('Passkey prompt cancelled. Nothing was changed.')).toBeTruthy()
    await waitFor(() => expect(api.count('DELETE /api/v1/page-settings/changes/ch-1')).toBe(1))
    expect(api.count('POST /api/v1/page-settings/changes/ch-1/save')).toBe(0)
  })
})
