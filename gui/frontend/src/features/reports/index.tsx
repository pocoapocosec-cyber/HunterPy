import { useState } from 'react'
import { LoadingSpinner } from '@components/common/LoadingSpinner'
import { useReports } from './hooks/useReports'
import { ReportList } from './components/ReportList'
import { ReportViewer } from './components/ReportViewer'
import { ReportGenerator } from './components/ReportGenerator'
import type { Report } from '@app-types/report'

export function ReportsFeature() {
  const { data, isLoading } = useReports()
  const [active, setActive] = useState<Report | null>(null)
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold">Reports</h1>
        <p className="text-sm text-text-muted">
          Browse historical reports and export new ones in JSON, HTML, or Markdown.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">
          {isLoading
            ? <LoadingSpinner />
            : <ReportList reports={data?.reports || []} onSelect={setActive} />}
          {active && <ReportViewer report={active} />}
        </div>
        <div><ReportGenerator /></div>
      </div>
    </div>
  )
}
