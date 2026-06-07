import { Link } from 'react-router-dom'
import type { Scan } from '@app-types/scan'
import { Card, CardContent } from '@components/ui/card'
import { Badge } from '@components/ui/badge'
import { Progress } from '@components/ui/progress'
import { ROUTES } from '@/config/routes'
import { formatRelative, formatDuration } from '@/lib/utils/formatters'

export function ScanCard({ scan }: { scan: Scan }) {
  const tone = scan.status === 'running' ? 'warn'
             : scan.status === 'completed' ? 'success'
             : scan.status === 'failed' ? 'danger' : 'default'
  return (
    <Link to={ROUTES.scanDetail(scan.id)}>
      <Card className="hover:border-brand/40 transition-colors">
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium">{scan.target}</div>
              <div className="text-xs text-text-muted">
                {scan.mode} · created {formatRelative(scan.created_at)}
              </div>
            </div>
            <Badge variant={tone as any}>{scan.status}</Badge>
          </div>

          {scan.status === 'running' && (
            <Progress value={scan.progress || 0} />
          )}

          <div className="flex justify-between text-xs text-text-muted pt-1
                          border-t border-line/30">
            <span>{scan.findings_count} finding(s)</span>
            {scan.duration != null && <span>{formatDuration(scan.duration)}</span>}
          </div>
        </CardContent>
      </Card>
    </Link>
  )
}
