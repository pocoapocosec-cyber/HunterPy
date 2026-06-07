import { Card, CardContent } from '@components/ui/card'
import { Activity, AlertOctagon, ShieldAlert, Target } from 'lucide-react'
import { LoadingSpinner } from '@components/common/LoadingSpinner'
import { useDashboardStats } from '../hooks/useDashboardStats'

export function StatsOverview() {
  const { data, isLoading } = useDashboardStats()

  if (isLoading) return <LoadingSpinner />

  const items = [
    { label: 'Total scans',    value: data?.total_scans ?? 0,        icon: Target,       tone: 'text-brand' },
    { label: 'Active scans',   value: data?.active_scans ?? 0,       icon: Activity,     tone: 'text-severity-medium' },
    { label: 'Findings',       value: data?.total_findings ?? 0,     icon: AlertOctagon, tone: 'text-text' },
    { label: 'Interesting',    value: data?.interesting_findings ?? 0, icon: ShieldAlert, tone: 'text-severity-critical' },
  ]

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {items.map((it) => {
        const Icon = it.icon
        return (
          <Card key={it.label}>
            <CardContent className="flex items-center gap-3">
              <div className={`p-2 rounded-md bg-line/30 ${it.tone}`}>
                <Icon className="h-5 w-5" />
              </div>
              <div>
                <div className="text-xs text-text-muted">{it.label}</div>
                <div className="text-2xl font-bold">{it.value}</div>
              </div>
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}
