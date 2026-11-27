import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Icon } from './Icon'
import styles from './DetailsTable.module.css'

export function DetailsTable({ label, columns, children }: { label: string; columns: readonly string[]; children: ReactNode }) {
  return (
    <div className={styles.frame}>
      <table aria-label={label} className={styles.table}>
        <thead>
          <tr>{columns.map(column => <th key={column} scope="col">{column}</th>)}</tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}

type RowLabel = { title: string; subtitle?: string; description?: string }

function DetailsLabel({ title, subtitle, description }: RowLabel) {
  return (
    <>
      <Icon name="chevron" />
      <span>
        <strong>{title}</strong>
        {subtitle ? <span className={styles.subtitle}>{subtitle}</span> : null}
        {description ? <> <span className="visually-hidden">{description}</span></> : null}
      </span>
    </>
  )
}

export function DetailsButton({ onClick, ...label }: RowLabel & { onClick: () => void }) {
  return (
    <button className={styles.open} type="button" aria-haspopup="dialog" onClick={onClick}>
      <DetailsLabel {...label} />
    </button>
  )
}

export function DetailsLink({ to, opensDialog, ...label }: RowLabel & { to: string; opensDialog?: boolean }) {
  return (
    <Link className={styles.open} to={to} aria-haspopup={opensDialog ? 'dialog' : undefined}>
      <DetailsLabel {...label} />
    </Link>
  )
}
