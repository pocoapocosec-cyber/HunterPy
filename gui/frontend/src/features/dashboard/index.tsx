import { useQuery } from '@tanstack/react-query'
import { scansAPI } from '@/lib/api/scans'
import { findingsAPI } from '@/lib/api/findings'
import { StatsOverview } from './components/StatsOverview'
import { RecentScans } from './components/RecentScans'
import { ActiveScansWidget } from './components/ActiveScansWidget'
import { QuickActions } from './components/QuickActions'
import { SeverityPieChart } from '@components/charts/SeverityPieChart'
import { FindingsTimelineChart } from '@components/charts/FindingsTimelineChart'
import { AttackSurfaceMap } from '@components/charts/AttackSurfaceMap'
import { LoadingSpinner } from '@components/common/LoadingSpinner'

export function DashboardFeature() {
  const { data: scans } = useQuery({
    queryKey: ['dashboard-recent-scans'],
    queryFn: () => scansAPI.list({ limit: 6 }),
  })
  const { data: findings, isLoading: floading } = useQuery({
    queryKey: ['dashboard-findings'],
    queryFn: () => findingsAPI.list({ limit: 500 }),
  })

  const sevCounts = (findings?.findings || []).reduce<Record<string, number>>(
    (acc, f) => {
      const s = (f.severity || 'info').toLowerCase()
      acc[s] = (acc[s] || 0) + 1
      return acc
    }, {}
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-sm text-text-muted">
            Live overview of scans, findings, and exposed attack surface.
          </p>
        </div>
        <QuickActions />
      </div>

      <StatsOverview />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <ActiveScansWidget />
        <SeverityPieChart data={sevCounts} />
        <AttackSurfaceMap findings={findings?.findings || []} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          {floading
            ? <LoadingSpinner />
            : <FindingsTimelineChart findings={findings?.findings || []} />}
        </div>
        <RecentScans scans={scans?.scans || []} />
      </div>
    </div>
  )
}
