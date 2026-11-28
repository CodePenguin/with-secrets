import { ChevronDown } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Button } from './Button'
import styles from './SplitButton.module.css'

type Item = { label: string; onSelect: () => void }

/** A primary action with an arrow beside it that opens the other ways to do it. Choosing one does it at once. */
export function SplitButton({ label, onPress, items, menuLabel, disabled }: { label: string; onPress?: () => void; items: readonly Item[]; menuLabel: string; disabled?: boolean }) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const toggle = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) return
    const outside = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('pointerdown', outside)

    return () => document.removeEventListener('pointerdown', outside)
  }, [open])

  useEffect(() => {
    if (disabled) setOpen(false)
  }, [disabled])

  function keys(event: React.KeyboardEvent) {
    if (event.key === 'Escape' && open) {
      // Closes the menu only: the dialog around it stays.
      event.preventDefault()
      event.stopPropagation()
      setOpen(false)
      toggle.current?.focus()
    }
    if ((event.key === 'ArrowDown' || event.key === 'ArrowUp') && open) {
      const entries = [...(root.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? [])]
      const at = entries.indexOf(document.activeElement as HTMLElement)
      event.preventDefault()
      entries[(at + (event.key === 'ArrowDown' ? 1 : -1) + entries.length) % entries.length]?.focus()
    }
  }

  if (items.length === 0) {
    return (
      <Button variant="primary" onClick={onPress} disabled={disabled}>
        {label}
      </Button>
    )
  }

  return (
    // The keys are for the menu inside; the buttons are the controls.
    // eslint-disable-next-line jsx-a11y/no-static-element-interactions
    <div className={styles.split} ref={root} onKeyDown={keys}>
      {onPress ? <Button variant="primary" className={styles.main} onClick={onPress} disabled={disabled}>
        {label}
      </Button> : null}
      <Button variant={onPress ? 'primary' : 'secondary'} className={onPress ? styles.arrow : undefined} ref={toggle}
        aria-label={menuLabel} aria-haspopup="menu" aria-expanded={open} disabled={disabled} onClick={() => setOpen(!open)}>
        {onPress ? null : label}
        <ChevronDown size="1em" strokeWidth={2.5} aria-hidden="true" focusable="false" />
      </Button>
      {open ? (
        <div role="menu" aria-label={menuLabel} className={styles.menu}>
          {items.map((item, index) => (
            <button
              key={item.label}
              type="button"
              role="menuitem"
              className={styles.item}
              // eslint-disable-next-line jsx-a11y/no-autofocus
              autoFocus={index === 0}
              onClick={() => {
                setOpen(false)
                item.onSelect()
              }}
            >
              {item.label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  )
}
