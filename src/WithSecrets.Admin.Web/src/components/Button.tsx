import type { ButtonHTMLAttributes, Ref } from 'react'
import styles from './Button.module.css'

type Props = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'danger' | 'dangerOutline' | 'quiet'; ref?: Ref<HTMLButtonElement> }

/** A native button with the shared look. `type` defaults to "button" so a button never submits a form by accident. */
export function Button({ variant = 'secondary', className, type = 'button', ...rest }: Props) {
  return <button {...rest} type={type} className={[styles.button, styles[variant], className].filter(Boolean).join(' ')} />
}

/** A link that looks like a button (opens a page: a real anchor, so it can be opened in a new tab by keyboard and mouse alike). */
export function ButtonLink({ variant = 'secondary', className, ...rest }: React.AnchorHTMLAttributes<HTMLAnchorElement> & { variant?: 'primary' | 'secondary' | 'danger' | 'quiet' }) {
  // The content is the children the caller passes.
  // eslint-disable-next-line jsx-a11y/anchor-has-content
  return <a {...rest} className={[styles.button, styles[variant], className].filter(Boolean).join(' ')} />
}
