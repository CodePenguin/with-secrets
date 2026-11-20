import { useEffect } from 'react'

/** The document title names the view (it is what a screen reader announces after a navigation). */
export function usePageTitle(title: string): void {
  useEffect(() => {
    document.title = `${title} - with-secrets administration`
  }, [title])
}
