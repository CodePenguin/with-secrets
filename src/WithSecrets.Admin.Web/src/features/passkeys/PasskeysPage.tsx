import { usePasskeys, useSession } from '../../api/queries'
import { Badge, Empty, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Loading, Notice, ProblemAlert } from '../../components/Feedback'
import list from '../../components/List.module.css'
import { Time } from '../../lib/format'
import { usePageTitle } from '../../lib/usePageTitle'
import { addPasskey, removePasskey } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'

export function PasskeysPage() {
  usePageTitle('Passkeys')
  const passkeys = usePasskeys(true)
  const start = useStartOperation()
  const session = useSession()
  const canChange = session.data?.capabilities.includes('admin.decide') === true

  return (
    <>
      <PageHeader title="Passkeys" />

      <p>Any enrolled passkey can view, approve and manage grants. Admin passkeys can also lock or unlock the authority and change settings, secrets and passkeys.</p>
      {canChange ? (
        <p>
          <Button variant="primary" onClick={() => start(addPasskey())}>Add a passkey...</Button>
        </p>
      ) : null}

      <h2 id="enrolled-passkeys">Enrolled passkeys</h2>
      {passkeys.isPending ? <Loading what="passkeys" /> : null}
      {passkeys.isError ? <ProblemAlert error={passkeys.error} title="The passkeys could not be listed" /> : null}
      {passkeys.data && !passkeys.data.available ? (
        <Notice kind="warning" title="Passkeys are not available">
          {passkeys.data.problem ?? 'The passkey store could not be read.'}
        </Notice>
      ) : null}
      {passkeys.data?.available && passkeys.data.items.length === 0 ? <Empty>No passkey is enrolled.</Empty> : null}
      {passkeys.data?.available && passkeys.data.items.length > 0 ? (
        <>
          <ul className={list.list} aria-labelledby="enrolled-passkeys">
            {passkeys.data.items.map((passkey) => (
              <li key={passkey.name} className={list.item}>
                <div className={list.itemHeader}>
                  <h3>{passkey.name}</h3>
                  <Badge tone={passkey.admin ? 'ok' : 'neutral'}>{passkey.admin ? 'admin' : 'convenience'}</Badge>
                </div>
                <Facts
                  items={[
                    ['Kind', passkey.detail],
                    ['Created', <Time key="c" value={passkey.created} />],
                  ]}
                />
                {canChange ? (
                  <div className={list.actions}>
                    <Button variant="danger" onClick={() => start(removePasskey(passkey))}>
                      Remove{' '}
                      <span className="visually-hidden">passkey {passkey.name}</span>
                    </Button>
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </>
  )
}
