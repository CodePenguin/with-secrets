import { Link } from 'react-router-dom'
import { useSettings } from '../../api/queries'
import { Card, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Loading, ProblemAlert } from '../../components/Feedback'
import { usePageTitle } from '../../lib/usePageTitle'
import { recoverAuthorityKey, rotateAuthorityKey, setAuditRetention, setSessionTimeouts, setUnlockPolicy } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'

export function SettingsPage() {
  usePageTitle('Settings')
  const settings = useSettings(true)
  const start = useStartOperation()

  if (settings.isPending) return <Loading what="the settings" />
  if (settings.isError) return <ProblemAlert error={settings.error} title="The settings could not be read" />
  const s = settings.data
  const manual = s.unlockMode === 'manual'

  return (
    <>
      <PageHeader title="Settings" />
      <Card title="Unlock mode">
        <Facts items={[['Current mode', s.unlockMode]]} />
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
        <Button onClick={() => start(setSessionTimeouts(s.sessionIdleMinutes, s.sessionAbsoluteMinutes, s.maxSessionIdleMinutes, s.maxSessionAbsoluteMinutes))}>Change session timeouts...</Button>
        <p>Manage the credentials that can administer this authority on the <Link to="/passkeys">Passkeys</Link> page.</p>
      </Card>

      <Card title="Authority signing key">
        <Facts items={[['Public fingerprint of the key in use', s.authorityKey]]} />
        <p>Rotating makes a transition that the current key signs and hosts follow. Recovering is for a lost key and makes every other host enroll again.</p>
        <p>
          <Button onClick={() => start(rotateAuthorityKey())}>Rotate the key...</Button> <Button variant="danger" onClick={() => start(recoverAuthorityKey())}>Recover the key...</Button>
        </p>
      </Card>
    </>
  )
}
