const formatter = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' })

/** A time in the person's own locale and zone, as a <time> element (the machine-readable value stays in dateTime). */
export function Time({ value }: { value: string | null | undefined }) {
  if (!value) return <>never</>
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return <>{value}</>

  return <time dateTime={value}>{formatter.format(date)}</time>
}
