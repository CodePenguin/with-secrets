import { useState } from 'react'
import { usePasskeys, useSession } from '../../api/queries'
import type { Passkey } from '../../api/types'
import { Badge, Empty, Facts, PageHeader } from '../../components/Card'
import { Button } from '../../components/Button'
import { DetailsButton, DetailsTable } from '../../components/DetailsTable'
import { Dialog } from '../../components/Dialog'
import { Icon } from '../../components/Icon'
import { Loading, Notice, ProblemAlert } from '../../components/Feedback'
import { Time } from '../../lib/format'
import { usePageTitle } from '../../lib/usePageTitle'
import { addPasskey, removePasskey } from '../authorization/operations'
import { useStartOperation } from '../authorization/OperationProvider'

function PasskeyRole({ passkey }: { passkey: Passkey }) {
  return <Badge tone={passkey.admin ? 'ok' : 'neutral'}>{passkey.admin ? 'Admin' : 'Approval'}</Badge>
}

export function PasskeysPage() {
  usePageTitle('Passkeys')
  const passkeys = usePasskeys(true)
  const start = useStartOperation()
  const session = useSession()
  const canChange = session.data?.capabilities.includes('admin.decide') === true
  const items = passkeys.data?.available ? passkeys.data.items : undefined
  const [selectedName, setSelectedName] = useState<string | null>(null)
  const selected = items?.find(passkey => passkey.name === selectedName)
  const close = () => setSelectedName(null)

  return (
    <>
      <PageHeader title="Passkeys">
        {canChange ? <Button variant="primary" onClick={() => start(addPasskey())}>Add passkey</Button> : null}
      </PageHeader>
      {passkeys.isPending ? <Loading what="passkeys" /> : null}
      {passkeys.isError ? <ProblemAlert error={passkeys.error} title="The passkeys could not be listed" /> : null}
      {passkeys.data && !passkeys.data.available ? (
        <Notice kind="warning" title="Passkeys are not available">
          {passkeys.data.problem ?? 'The passkey store could not be read.'}
        </Notice>
      ) : null}
      {items?.length === 0 ? <Empty>No passkey is enrolled.</Empty> : null}
      {items && items.length > 0 ? (
        <DetailsTable label="Enrolled passkeys" columns={['Name', 'Role', 'Created']}>
          {items.map(passkey => (
            <tr key={passkey.name}>
              <th scope="row"><DetailsButton title={passkey.name} description="View passkey" onClick={() => setSelectedName(passkey.name)} /></th>
              <td><PasskeyRole passkey={passkey} /></td>
              <td><Time value={passkey.created} /></td>
            </tr>
          ))}
        </DetailsTable>
      ) : null}
      {selected ? (
        <Dialog title={selected.name} onCancel={close} footer={
          <>
            <Button onClick={close}>Close</Button>
            {canChange ? (
              <Button variant="dangerOutline" onClick={() => {
                close()
                start(removePasskey(selected))
              }}><Icon name="trash" /> Remove passkey</Button>
            ) : null}
          </>
        }>
          <Facts items={[
            ['Role', <PasskeyRole passkey={selected} />],
            ['Kind', selected.detail],
            ['Created', <Time value={selected.created} />],
          ]} />
          <p>{selected.admin
            ? 'Admin passkeys can approve runs, manage grants, manage secrets and passkeys, change settings, and lock or unlock the service.'
            : 'Approval passkeys can approve runs and manage grants.'}</p>
        </Dialog>
      ) : null}
    </>
  )
}
