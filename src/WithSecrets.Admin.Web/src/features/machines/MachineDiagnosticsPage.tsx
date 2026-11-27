import { Link, useParams } from 'react-router-dom'
import { useMachineDiagnostics } from '../../api/queries'
import { Badge, Card, Empty, Facts, PageHeader } from '../../components/Card'
import { DetailsTable } from '../../components/DetailsTable'
import { Loading, ProblemAlert } from '../../components/Feedback'
import { Time } from '../../lib/format'
import { usePageTitle } from '../../lib/usePageTitle'

export function MachineDiagnosticsPage() {
  usePageTitle('Machine diagnostics')
  const { fingerprint = '' } = useParams()
  const diagnostics = useMachineDiagnostics(fingerprint)
  const data = diagnostics.data

  return (
    <>
      <PageHeader title="Diagnostics"><Link to="/machines">Back to machines</Link></PageHeader>
      {diagnostics.isPending ? <Loading what="diagnostics" /> : null}
      {diagnostics.error ? <ProblemAlert error={diagnostics.error} title="Could not load diagnostics" /> : null}
      {data ? (
        <Card title={data.machineName}>
          <Facts items={[
            ['Last received', data.lastReceivedAt ? <Time key="last" value={data.lastReceivedAt} /> : 'No entries received'],
          ]} />
          {data.items.length ? (
            <DetailsTable label="Diagnostic log" columns={['Recorded', 'Received', 'Severity', 'Component', 'Message']}>
              {data.items.map(item => (
                <tr key={item.id}>
                  <td><Time value={item.time} /></td>
                  <td><Time value={item.receivedAt} /></td>
                  <td><Badge tone="warn">Warning</Badge></td>
                  <td>{item.component}</td>
                  <td>{item.message}</td>
                </tr>
              ))}
            </DetailsTable>
          ) : <Empty>No diagnostics have been received from this machine.</Empty>}
        </Card>
      ) : null}
    </>
  )
}
