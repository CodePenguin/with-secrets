import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Notice, useAnnounce } from './Feedback'

/** Passed with a navigation (`navigate(path, { state: flash('...') })`) to say at the top of the next page what the last action did. */
export function flash(message: string): { flash: string } {
  return { flash: message }
}

/** The message the person was sent here with, once: it is read, announced and taken out of the history entry, so a reload does not show it again. */
export function Flash() {
  const location = useLocation()
  const navigate = useNavigate()
  const announce = useAnnounce()
  const [message] = useState(() => (location.state as { flash?: unknown } | null)?.flash)
  const text = typeof message === 'string' ? message : null

  useEffect(() => {
    if (text === null) return
    announce(text)
    navigate(location.pathname, { replace: true, state: null })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps -- once, when the page opens

  return text === null ? null : <Notice kind="ok">{text}</Notice>
}
