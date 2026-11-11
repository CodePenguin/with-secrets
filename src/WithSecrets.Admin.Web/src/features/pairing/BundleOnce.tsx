import { useState } from 'react'
import type { InvitationCreated } from '../../api/types'
import { Button } from '../../components/Button'
import { Notice } from '../../components/Feedback'
import { Time } from '../../lib/format'
import styles from './BundleOnce.module.css'

/**
 * The invitation bundle, shown ONCE: it lives only in the dialog's state (never in a query, a URL or storage) and is gone when the dialog closes.
 * The service cannot show it again.
 */
export function BundleOnce({ invitation }: { invitation: InvitationCreated }) {
  const [copied, setCopied] = useState<'no' | 'yes' | 'failed'>('no')

  async function copy() {
    try {
      await navigator.clipboard.writeText(invitation.bundle)
      setCopied('yes')
    } catch {
      setCopied('failed')
    }
  }

  return (
    <div className={styles.once}>
      <Notice kind="warning" title="This invitation is shown only now">
        Copy it before you close this dialog. It cannot be shown again, and anyone who has it can pair one machine until it is used or expires (<Time value={invitation.expires} />).
      </Notice>
      <label htmlFor="pairing-bundle">Invitation bundle</label>
      <textarea id="pairing-bundle" className={styles.bundle} readOnly rows={4} spellCheck={false} autoComplete="off" value={invitation.bundle} onFocus={(event) => event.currentTarget.select()} />
      <p>
        <Button onClick={() => void copy()}>Copy the invitation</Button>{' '}
        <span role="status">{copied === 'yes' ? 'Copied.' : copied === 'failed' ? 'Copying was not possible here; select the text and copy it.' : ''}</span>
      </p>
      <p>
        On the new machine run <code>with-secrets pair</code> and paste the bundle at the hidden prompt. For an unattended machine put it in a secret file (a Docker secret) and name that file in <code>WITH_SECRETS_PAIRING_FILE</code>. Then approve the machine here after checking its fingerprint and host name.
      </p>
    </div>
  )
}
