import { Navigate, Route, Routes } from 'react-router-dom'
import { AuditPage } from './features/audit/AuditPage'
import { GrantsPage } from './features/grants/GrantsPage'
import { MachinesPage } from './features/machines/MachinesPage'
import { PasskeysPage } from './features/passkeys/PasskeysPage'
import { SettingsPage } from './features/settings/SettingsPage'
import { Shell } from './features/shell/Shell'
import { OverviewPage } from './features/status/OverviewPage'

/** The views are addresses (under /admin): a link, the back button and a reload all land on the same view. Dialogs are for one change at a time. */
export function App() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<OverviewPage />} />
        <Route path="machines" element={<MachinesPage />} />
        <Route path="pairing" element={<Navigate to="/machines" replace />} />
        <Route path="grants" element={<GrantsPage />} />
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
