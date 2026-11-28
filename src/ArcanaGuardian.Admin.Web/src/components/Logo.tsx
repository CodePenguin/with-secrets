import dark from '../assets/logo-dark.svg'
import light from '../assets/logo-light.svg'

/** The Arcana Guardian mark and name. The person's colour scheme picks the artwork, as it does the colours. */
export function Logo({ className }: { className?: string }) {
  return (
    <picture>
      <source media="(prefers-color-scheme: dark)" srcSet={dark} />
      <img src={light} alt="Arcana Guardian" className={className} />
    </picture>
  )
}
