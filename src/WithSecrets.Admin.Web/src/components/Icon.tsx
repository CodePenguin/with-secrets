import { ArrowRight, Check, ChevronRight, Folder, FolderInput, KeyRound, Link2, Lock, LockOpen, Pencil, Plus, Trash2 } from 'lucide-react'
import styles from './Icon.module.css'

const icons = {
  key: KeyRound,
  folder: Folder,
  mount: FolderInput,
  lock: Lock,
  unlock: LockOpen,
  check: Check,
  plus: Plus,
  edit: Pencil,
  trash: Trash2,
  link: Link2,
  arrow: ArrowRight,
  chevron: ChevronRight,
} as const

export type IconName = keyof typeof icons

/** A decorative icon. Its surrounding label names the action. */
export function Icon({ name }: { name: IconName }) {
  const Picture = icons[name]
  return <Picture size="1em" strokeWidth={2} aria-hidden="true" focusable="false" className={styles.icon} />
}

/** A short left-to-right flow: each step is a picture and a word, joined by arrows. */
export function Flow({ steps, label }: { steps: ReadonlyArray<{ icon: IconName; text: string }>; label: string }) {
  return (
    <ol aria-label={label} className={styles.flow}>
      {steps.map((step, index) => (
        <li key={step.text} className={styles.step}>
          {index > 0 ? <Icon name="arrow" /> : null}
          <Icon name={step.icon} /> {step.text}
        </li>
      ))}
    </ol>
  )
}
