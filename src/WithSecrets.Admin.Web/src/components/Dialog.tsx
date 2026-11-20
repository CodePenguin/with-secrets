import { useEffect, useId, useRef, type ReactNode } from 'react'
import styles from './Dialog.module.css'

type Props = {
  title: string
  children: ReactNode
  footer?: ReactNode
  /** Esc and the close button. */
  onCancel: () => void
  /** When this value changes (a new step), focus moves to the heading so a screen reader reads the new step. */
  step?: string
}

/**
 * A modal dialog on the native <dialog> element: the browser traps focus inside, makes the rest of the page inert, closes on Esc
 * (routed to onCancel here) and returns focus to the control that opened it. Clicking outside does not close it.
 */
export function Dialog({ title, children, footer, onCancel, step }: Props) {
  const ref = useRef<HTMLDialogElement>(null)
  const heading = useRef<HTMLHeadingElement>(null)
  const titleId = useId()
  const first = useRef(true)

  useEffect(() => {
    const dialog = ref.current
    // Where focus was when the dialog opened (the control that opened it): focus goes back there when it closes.
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    if (dialog && !dialog.open) dialog.showModal()

    return () => {
      if (dialog?.open) dialog.close()
      // The page may have re-rendered meanwhile: if the opener is gone, focus lands on the view's heading.
      queueMicrotask(() => {
        if (opener?.isConnected) opener.focus()
        else {
          const heading = document.querySelector<HTMLElement>('main h1')
          if (heading) {
            heading.tabIndex = -1
            heading.focus()
          }
        }
      })
    }
  }, [])

  useEffect(() => {
    if (first.current) {
      first.current = false

      return
    }
    heading.current?.focus()
  }, [step])

  return (
    <dialog
      ref={ref}
      className={styles.dialog}
      aria-labelledby={titleId}
      data-step={step}
      onCancel={(event) => {
        event.preventDefault()
        onCancel()
      }}
    >
      <div className={styles.inner}>
        <h2 id={titleId} ref={heading} tabIndex={-1} className={styles.title}>
          {title}
        </h2>
        <div className={styles.body}>{children}</div>
        {footer ? <div className={styles.footer}>{footer}</div> : null}
      </div>
    </dialog>
  )
}
