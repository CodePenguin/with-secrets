import { useAuthenticators, useSession, useStatus } from '../../api/queries'
import { Button } from '../../components/Button'
import { Card, Empty, PageHeader } from '../../components/Card'
import { Loading, ProblemAlert } from '../../components/Feedback'
import { usePageTitle } from '../../lib/usePageTitle'
import { addAuthenticator, removeAuthenticator } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'

export function AccessCredentialsPage() {
  usePageTitle('Access credentials')
  const items = useAuthenticators()
  const session = useSession()
  const status = useStatus()
  const start = useStartOperation()
  const canManage = session.data?.capabilities.includes('admin.decide') && status.data?.locked === false

  return (
    <>
      <PageHeader title="Access credentials" />
      <Card title="Authenticator apps">
        <p>Use a code from an enrolled app to resume editing in an existing admin session.</p>
        {items.isPending ? <Loading what="authenticator apps" /> : null}
        {items.isError ? <ProblemAlert error={items.error} title="The authenticator apps could not be read" /> : null}
        {items.data?.length === 0 ? <Empty>No authenticator apps are enrolled.</Empty> : null}
        {items.data?.length ? (
          <ul>
            {items.data.map(item => (
              <li key={item.id}>
                {item.name}{' '}
                {canManage ? <Button variant="quiet" aria-label={'Remove ' + item.name} onClick={() => start(removeAuthenticator(item.id, item.name))}>Remove</Button> : null}
              </li>
            ))}
          </ul>
        ) : null}
        {canManage ? <Button variant="primary" onClick={() => start(addAuthenticator())}>Add authenticator app</Button> : null}
      </Card>
    </>
  )
}
