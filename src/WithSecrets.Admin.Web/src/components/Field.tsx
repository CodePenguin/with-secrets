import { useId, type ReactNode } from 'react'
import styles from './Field.module.css'

type ControlProps = { id: string; 'aria-describedby'?: string; 'aria-invalid'?: true; 'aria-required'?: true }

type Props = {
  label: string
  hint?: string
  error?: string
  required?: boolean
  children: (control: ControlProps) => ReactNode
}

/** A label, an optional hint and an error that is tied to the control (aria-describedby, aria-invalid). The error is read out when it appears (role="alert"). */
export function Field({ label, hint, error, required, children }: Props) {
  const id = useId()
  const hintId = hint ? id + '-hint' : undefined
  const errorId = error ? id + '-error' : undefined
  const described = [hintId, errorId].filter(Boolean).join(' ') || undefined

  return (
    <div className={styles.field}>
      <label htmlFor={id} className={styles.label}>
        {label}
        {required ? <span className={styles.required}> (required)</span> : null}
      </label>
      {hint ? (
        <p id={hintId} className={styles.hint}>
          {hint}
        </p>
      ) : null}
      {children({ id, 'aria-describedby': described, ...(error ? { 'aria-invalid': true as const } : {}), ...(required ? { 'aria-required': true as const } : {}) })}
      {error ? (
        <p id={errorId} className={styles.error} role="alert">
          <span aria-hidden="true">Error: </span>
          {error}
        </p>
      ) : null}
    </div>
  )
}

export const controlClass = styles.control as string
export const checkClass = styles.check as string
