import type { Report } from '@app-types/report'
import { Card, CardContent } from '@components/ui/card'
import { Badge } from '@components/ui/badge'
import { formatDate } from '@/lib/utils/formatters'

export function ReportList({ reports, onSelect }:
  { reports: Report[]; onSelect: (r: Report) => void }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      {reports.map((r) => (
        <Card key={r.id} className="cursor-pointer hover:border-brand/40"
              onClick={() => onSelect(r)}>
          <CardContent className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="font-medium">{r.title}</div>
              <Badge variant="outline" className="uppercase text-[10px]">
                {r.format}
              </Badge>
            </div>
            <div className="text-xs text-text-muted">
              generated {formatDate(r.generated_at)}
            </div>
            <div className="text-xs text-text-muted">
              {r.statistics.total_findings} findings · scan {r.scan_id}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
