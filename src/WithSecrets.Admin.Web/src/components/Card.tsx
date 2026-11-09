import type { ReactNode } from 'react'
import styles from './Card.module.css'

export function PageHeader({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className={styles.pageHeader}>
      <h1>{title}</h1>
      {children ? <div className={styles.pageActions}>{children}</div> : null}
    </div>
  )
}

export function Card({ title, children, as: Heading = 'h2' }: { title?: string; children: ReactNode; as?: 'h2' | 'h3' }) {
  return (
    <section className={styles.card}>
      {title ? <Heading className={styles.cardTitle}>{title}</Heading> : null}
      {children}
    </section>
  )
}

/** Name and value pairs (a real description list: screen readers announce the terms). */
export function Facts({ items }: { items: ReadonlyArray<readonly [string, ReactNode]> }) {
  return (
    <dl className={styles.facts}>
      {items.map(([name, value]) => (
        <div key={name} className={styles.fact}>
          <dt>{name}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  )
}

/** A state with words (and a mark), never colour alone. */
export function Badge({ tone, children }: { tone: 'ok' | 'warn' | 'bad' | 'neutral'; children: ReactNode }) {
  const mark = tone === 'ok' ? '✓ ' : tone === 'bad' ? '✕ ' : tone === 'warn' ? '! ' : ''

  return (
    <span className={[styles.badge, styles['tone-' + tone]].join(' ')}>
      <span aria-hidden="true">{mark}</span>
      {children}
    </span>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className={styles.empty}>{children}</p>
}
