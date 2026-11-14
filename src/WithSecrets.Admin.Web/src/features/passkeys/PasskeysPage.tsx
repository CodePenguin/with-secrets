import { Link } from 'react-router-dom'
import { usePasskeys } from '../../api/queries'
import { Badge, Empty, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { Loading, Notice, ProblemAlert } from '../../components/Feedback'
import list from '../../components/List.module.css'
import { Time } from '../../lib/format'
import { usePageTitle } from '../../lib/usePageTitle'
import { addPasskey, removePasskey } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'
import styles from './PasskeysPage.module.css'

export function PasskeysPage() {
  usePageTitle('Passkeys')
  const passkeys = usePasskeys(true)
  const start = useStartOperation()

  return (
    <>
      <PageHeader title="Passkeys" />
      <p>Credentials that approve requests and administer this authority. Private key material is never displayed.</p>

      <section className={styles.roles} aria-labelledby="passkey-roles">
        <h2 id="passkey-roles">Roles</h2>
        <Facts
          items={[
            ['Admin', 'May administer authority state, including settings and passkey management.'],
            ['Approval only', 'May approve eligible secret-use requests but cannot administer authority state.'],
          ]}
        />
        <p>The kind describes the credential; the badge shows what it is allowed to do.</p>
      </section>

      <p>Adding a passkey starts a delegated enrollment sequence. The first tap authorizes the start; each enrollment page then needs its own passkey tap.</p>
      <p>
        <Button variant="primary" onClick={() => start(addPasskey())}>
          Add a passkey...
        </Button>
      </p>
      <p>For authority behavior and signing-key maintenance, see <Link to="/settings">Settings</Link>.</p>

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
                  <Badge tone={passkey.admin ? 'ok' : 'neutral'}>{passkey.admin ? 'admin' : 'approval only'}</Badge>
                </div>
                <Facts
                  items={[
                    ['Kind', passkey.detail],
                    ['Created', <Time key="c" value={passkey.created} />],
                  ]}
                />
                <div className={list.actions}>
                  <Button variant="danger" onClick={() => start(removePasskey(passkey))}>
                    Remove{' '}
                    <span className="visually-hidden">passkey {passkey.name}</span>
                  </Button>
                </div>
              </li>
            ))}
          </ul>
          <p className={styles.note}>The last admin passkey cannot be removed.</p>
        </>
      ) : null}
    </>
  )
}
