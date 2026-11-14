import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useSettings } from '../../api/queries'
import { Card, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Loading, ProblemAlert } from '../../components/Feedback'
import { usePageTitle } from '../../lib/usePageTitle'
import { recoverAuthorityKey, rotateAuthorityKey, setAuditRetention, setSessionTimeouts, setUnlockPolicy } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'
import styles from './SettingsPage.module.css'

export function SettingsPage() {
  usePageTitle('Settings')
  const settings = useSettings(true)
  const start = useStartOperation()
  const [copied, setCopied] = useState<'no' | 'yes' | 'failed'>('no')

  if (settings.isPending) return <Loading what="the settings" />
  if (settings.isError) return <ProblemAlert error={settings.error} title="The settings could not be read" />
  const s = settings.data
  const manual = s.unlockMode === 'manual'

  async function copyFingerprint() {
    try {
      await navigator.clipboard.writeText(s.authorityKey)
      setCopied('yes')
    } catch {
      setCopied('failed')
    }
  }

  return (
    <>
      <PageHeader title="Settings" />
      <p>How this authority behaves and how its signing key is maintained.</p>

      <Card title="Unlock mode">
        <Facts items={[['Current mode', manual ? 'Manual' : 'Unattended']]} />
        <p>{s.unlockModeDescription}</p>
        <Button variant={manual ? 'secondary' : 'primary'} onClick={() => start(setUnlockPolicy(manual ? 'unattended' : 'manual'))}>
          {manual ? 'Allow unattended unlock...' : 'Require a manual unlock...'}
        </Button>
      </Card>

      <Card title="Audit retention">
        <Facts items={[['Keep events for', s.auditRetentionDays === 0 ? 'ever (no limit)' : `${s.auditRetentionDays} days`]]} />
        <Button onClick={() => start(setAuditRetention(s.auditRetentionDays, s.maxAuditRetentionDays))}>Change audit retention...</Button>
      </Card>

      <Card title="Administrator sessions">
        <Facts
          items={[
            ['Idle timeout', `${s.sessionIdleMinutes} minutes`],
            ['Absolute timeout', `${s.sessionAbsoluteMinutes} minutes`],
          ]}
        />
        <p>An idle timeout ends a session after that long without use. An absolute timeout ends it after that long however busy it is.</p>
        <Button onClick={() => start(setSessionTimeouts(s.sessionIdleMinutes, s.sessionAbsoluteMinutes, s.maxSessionIdleMinutes, s.maxSessionAbsoluteMinutes))}>Change session timeouts...</Button>
        <p>Manage the credentials that can administer this authority on the <Link to="/passkeys">Passkeys</Link> page.</p>
      </Card>

      <Card title="Authority signing key">
        <Facts
          items={[
            [
              'Public fingerprint',
              <div key="fingerprint" className={styles.fingerprint}>
                <code className={styles.mono}>{s.authorityKey}</code>
                <Button variant="quiet" onClick={() => void copyFingerprint()}>
                  Copy public fingerprint
                </Button>
                <span role="status" className={styles.copyStatus}>
                  {copied === 'yes' ? 'Copied.' : copied === 'failed' ? 'Copying was not possible here; select the fingerprint and copy it.' : ''}
                </span>
              </div>,
            ],
          ]}
        />
        <p>Rotate the key: the current key signs a transition that hosts can follow. Recover the key: use only if the key is lost; it makes no transition and every other host must enroll again.</p>
        <p>
          <Button onClick={() => start(rotateAuthorityKey())}>Rotate the key...</Button> <Button variant="danger" onClick={() => start(recoverAuthorityKey())}>Recover the key...</Button>
        </p>
      </Card>
    </>
  )
}
