import { Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { MainLayout } from '@components/layout/MainLayout'
import { ErrorBoundary } from '@components/common/ErrorBoundary'
import { LoadingSpinner } from '@components/common/LoadingSpinner'
import { AuthGuard } from '@features/auth/components/AuthGuard'
import { ROUTES } from '@/config/routes'

import { Dashboard }   from '@pages/Dashboard'
import { Scans }       from '@pages/Scans'
import { NewScan }     from '@pages/NewScan'
import { ScanDetail }  from '@pages/ScanDetail'
import { Findings }    from '@pages/Findings'
import { FindingDetail } from '@pages/FindingDetail'
import { Reports }     from '@pages/Reports'
import { Settings }    from '@pages/Settings'
import { Login }       from '@pages/Login'
import { NotFound }    from '@pages/NotFound'

export default function App() {
  return (
    <ErrorBoundary>
      <Suspense fallback={<div className="p-6"><LoadingSpinner /></div>}>
        <Routes>
          <Route path={ROUTES.login} element={<Login />} />
          <Route element={<AuthGuard><MainLayout /></AuthGuard>}>
            <Route path={ROUTES.dashboard}        element={<Dashboard />} />
            <Route path={ROUTES.scans}            element={<Scans />} />
            <Route path={ROUTES.newScan}          element={<NewScan />} />
            <Route path="/scans/:scanId"          element={<ScanDetail />} />
            <Route path={ROUTES.findings}         element={<Findings />} />
            <Route path="/findings/:findingId"    element={<FindingDetail />} />
            <Route path={ROUTES.reports}          element={<Reports />} />
            <Route path={ROUTES.settings}         element={<Settings />} />
          </Route>
          <Route path="*" element={<Navigate to={ROUTES.dashboard} replace />} />
          <Route path="/404" element={<NotFound />} />
        </Routes>
      </Suspense>
    </ErrorBoundary>
  )
}
