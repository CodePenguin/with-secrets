import { Navigate, Route, Routes } from 'react-router-dom'
import { SecretsPage } from './features/secrets/SecretsPage'
import { AccessCredentialsPage } from './features/access-credentials/AccessCredentialsPage'
import { AccessPage } from './features/access/AccessPage'
import { AuditPage } from './features/audit/AuditPage'
import { MachinesPage } from './features/machines/MachinesPage'
import { MachineDiagnosticsPage } from './features/machines/MachineDiagnosticsPage'
import { PasskeysPage } from './features/passkeys/PasskeysPage'
import { ProvidersPage } from './features/providers/ProvidersPage'
import { SettingsPage } from './features/settings/SettingsPage'
import { SignInPage } from './features/session/SignInPage'
import { Shell } from './features/shell/Shell'
import { OverviewPage } from './features/status/OverviewPage'

/** The views are addresses (under /admin): a link, the back button and a reload all land on the same view. Dialogs are for one change at a time. */
export function App() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<OverviewPage />} />
        <Route path="sign-in" element={<SignInPage />} />
        <Route path="access-credentials" element={<AccessCredentialsPage />} />
        <Route path="access" element={<AccessPage />} />
        <Route path="secrets" element={<SecretsPage />} />
        <Route path="providers" element={<ProvidersPage />} />
        <Route path="providers/:id" element={<ProvidersPage />} />
        <Route path="access/:requestId" element={<AccessPage />} />
        <Route path="machines" element={<MachinesPage />} />
        <Route path="machines/:fingerprint/diagnostics" element={<MachineDiagnosticsPage />} />
        <Route path="audit" element={<AuditPage view="events" />} />
        <Route path="audit/changes" element={<AuditPage view="changes" />} />
        <Route path="audit/gaps" element={<AuditPage view="gaps" />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="passkeys" element={<PasskeysPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
