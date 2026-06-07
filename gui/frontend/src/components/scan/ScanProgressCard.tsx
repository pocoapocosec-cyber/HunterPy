import { Activity } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { Progress } from '@components/ui/progress'
import { Badge } from '@components/ui/badge'
import { formatDuration } from '@/lib/utils/formatters'
import type { ScanProgress } from '@app-types/scan'

export function ScanProgressCard({ progress, findingsCount }:
  { progress: ScanProgress | null; findingsCount: number }) {
  if (!progress) return null
  const variant = progress.status === 'failed' ? 'danger'
                : progress.status === 'completed' ? 'success'
                : 'default'

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Scan progress</CardTitle>
        <Badge variant={variant === 'success' ? 'success'
                        : variant === 'danger' ? 'danger' : 'default'}>
          {progress.status}
        </Badge>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <div className="flex justify-between text-sm mb-1">
            <span className="font-medium">{progress.phase_name}</span>
            <span className="text-text-muted">{progress.percent}%</span>
          </div>
          <Progress value={progress.percent} variant={variant} />
        </div>

        {progress.current_module && (
          <div className="flex items-center gap-2 text-sm">
            <Activity className="h-4 w-4 text-brand animate-scan-pulse" />
            Running: <span className="font-medium">{progress.current_module}</span>
          </div>
        )}

        <div className="grid grid-cols-3 gap-4 pt-2 border-t border-line/30">
          <Stat label="Modules"
                value={`${progress.modules_completed} / ${progress.modules_total}`} />
          <Stat label="Findings" value={findingsCount} />
          <Stat label="Elapsed" value={formatDuration(progress.elapsed_time)} />
        </div>

        {progress.estimated_remaining > 0 && (
          <p className="text-center text-xs text-text-muted">
            ~{formatDuration(progress.estimated_remaining)} remaining
          </p>
        )}
      </CardContent>
    </Card>
  )
}

function Stat({ label, value }: { label: string; value: any }) {
  return (
    <div>
      <div className="text-xs text-text-muted">{label}</div>
      <div className="font-semibold">{value}</div>
    </div>
  )
}
