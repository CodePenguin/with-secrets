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
  const incoming = (location.state as { flash?: unknown } | null)?.flash
  const [text, setText] = useState<string | null>(() => typeof incoming === 'string' ? incoming : null)

  useEffect(() => {
    if (typeof incoming !== 'string') return
    setText(incoming)
    announce(incoming)
    navigate(location.pathname + location.search + location.hash, { replace: true, state: null })
  }, [incoming, location.key]) // eslint-disable-line react-hooks/exhaustive-deps -- once per incoming history entry

  return text === null ? null : <div data-page-feedback><Notice kind="ok">{text}</Notice></div>
}
