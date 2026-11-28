import { useId, useState, type FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import { keys } from '../../api/queries'
import type { components } from '../../api/schema'
import { Button } from '../../components/Button'
import { Dialog } from '../../components/Dialog'
import { Field, controlClass } from '../../components/Field'
import { ProblemAlert } from '../../components/Feedback'

type Authenticator = components['schemas']['Authenticators']['items'][number]

export function AuthenticatorResumeDialog({ items, onClose, onPasskey }: {
  items: Authenticator[]
  onClose: () => void
  onPasskey: () => void
}) {
  const formId = useId()
  const client = useQueryClient()
  const [id, setId] = useState(items[0]?.id ?? '')
  const [code, setCode] = useState('')
  const resume = useMutation({
    mutationFn: () => api.post('/api/v1/session/resume/authenticator', { body: { id, code } }),
    onSuccess: () => {
      onClose()
      void client.invalidateQueries({ queryKey: keys.session })
    },
    onError: () => setCode(''),
  })

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (/^[0-9]{6}$/.test(code) && !resume.isPending) resume.mutate()
  }

  return (
    <Dialog title="Resume editing" onCancel={onClose} footer={
      <>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={onPasskey}>Use admin passkey</Button>
        <Button type="submit" form={formId} variant="primary" disabled={!/^[0-9]{6}$/.test(code) || resume.isPending}>Resume editing</Button>
      </>
    }>
      {resume.isError ? <ProblemAlert error={resume.error} title="Editing is still locked" /> : null}
      <form id={formId} onSubmit={submit}>
        {items.length > 1 ? <Field label="Authenticator app">{control => (
          <select {...control} className={controlClass} value={id} onChange={event => setId(event.target.value)}>
            {items.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
        )}</Field> : <p>Enter the code from {items[0]?.name}.</p>}
        <Field label="Six-digit code" required>{control => (
          <input {...control} className={controlClass} value={code} inputMode="numeric" autoComplete="one-time-code"
            pattern="[0-9]{6}" maxLength={6} onChange={event => setCode(event.target.value)} />
        )}</Field>
      </form>
    </Dialog>
  )
}
