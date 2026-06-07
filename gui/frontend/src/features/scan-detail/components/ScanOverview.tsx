import type { Scan } from '@app-types/scan'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { Badge } from '@components/ui/badge'
import { formatDate, formatDuration } from '@/lib/utils/formatters'
import { ScanPhaseIndicator } from '@components/scan/ScanPhaseIndicator'

export function ScanOverview({ scan }: { scan: Scan }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>{scan.target}</CardTitle>
          <Badge variant={
            scan.status === 'completed' ? 'success'
              : scan.status === 'failed' ? 'danger'
              : scan.status === 'running' ? 'warn' : 'default'
          }>{scan.status}</Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <KV label="Mode"     value={scan.mode} />
          <KV label="Findings" value={scan.findings_count} />
          <KV label="Duration" value={scan.duration ? formatDuration(scan.duration) : '—'} />
          <KV label="Started"  value={formatDate(scan.started_at || scan.created_at)} />
        </div>
        <ScanPhaseIndicator current={scan.phase} />
      </CardContent>
    </Card>
  )
}

function KV({ label, value }: { label: string; value: any }) {
  return (
    <div>
      <div className="text-xs text-text-muted">{label}</div>
      <div className="font-medium">{String(value ?? '—')}</div>
    </div>
  )
}
