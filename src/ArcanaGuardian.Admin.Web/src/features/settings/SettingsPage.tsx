import { useState } from 'react'
import { useSession, useSettings, useStatus } from '../../api/queries'
import { PageSettingsCard } from './PageSettingsCard'
import { Card, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Loading, ProblemAlert } from '../../components/Feedback'
import { usePageTitle } from '../../lib/usePageTitle'
import { recoverAuthorityKey, rotateAuthorityKey, rotateStoreKey, setAuditRetention, setSessionTimeouts } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'
import styles from './SettingsPage.module.css'

export function SettingsPage() {
  usePageTitle('Settings')
  const settings = useSettings(true)
  const status = useStatus()
  const session = useSession()
  const canChange = session.data?.capabilities.includes('admin.decide') === true
  const start = useStartOperation()
  const [copied, setCopied] = useState<'no' | 'yes' | 'failed'>('no')

  if (settings.isPending) return <Loading what="the settings" />
  if (settings.isError) return <ProblemAlert error={settings.error} title="The settings could not be read" />
  const s = settings.data

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

      {status.data && !status.data.remote ? (
        <Card title="Review access">
          <Facts items={[['Review text', status.data.reviewOpen ? 'open' : 'locked']]} />
        </Card>
      ) : null}

      <Card title="Audit retention">
        <Facts items={[['Keep events for', s.auditRetentionDays === 0 ? 'Forever' : `${s.auditRetentionDays} days`]]} />
        {canChange ? <Button onClick={() => start(setAuditRetention(s.auditRetentionDays, s.maxAuditRetentionDays))}>Change audit retention...</Button> : null}
      </Card>

      <Card title="Administrator sessions">
        <Facts
          items={[
            ['Lock editing after inactivity', s.sessionIdleMinutes === 0 ? 'Never' : `${s.sessionIdleMinutes} minutes`],
            ['Sign out after', `${s.sessionAbsoluteMinutes} minutes, however busy`],
          ]}
        />
        {canChange ? <Button onClick={() => start(setSessionTimeouts(s.sessionIdleMinutes, s.sessionAbsoluteMinutes, s.maxSessionIdleMinutes, s.maxSessionAbsoluteMinutes))}>Change session timeouts...</Button> : null}
      </Card>

      <PageSettingsCard canChange={canChange} />

      {canChange ? (
        <Card title="Secret store key">
          <p>Replaces the key that protects your secrets and shows a new recovery code once. Do it if a passkey may have been seen.</p>
          <Button variant="danger" onClick={() => start(rotateStoreKey())}>Rotate the secret store key...</Button>
        </Card>
      ) : null}

      <Card title="Authority signing key">
        <Facts
          items={[
            [
              'Fingerprint',
              <div key="fingerprint" className={styles.fingerprint}>
                <code className={styles.mono}>{s.authorityKey}</code>
                <Button variant="quiet" onClick={() => void copyFingerprint()}>
                  Copy fingerprint
                </Button>
                <span role="status" className={styles.copyStatus}>
                  {copied === 'yes' ? 'Copied.' : copied === 'failed' ? 'Copying was not possible here; select the fingerprint and copy it.' : ''}
                </span>
              </div>,
            ],
          ]}
        />
        {canChange ? (
          <p>
            <Button onClick={() => start(rotateAuthorityKey())}>Rotate the key...</Button> <Button variant="danger" onClick={() => start(recoverAuthorityKey())}>Recover the key...</Button>
          </p>
        ) : null}
      </Card>
    </>
  )
}
