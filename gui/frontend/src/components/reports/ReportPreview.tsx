import type { Report } from '@app-types/report'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'

export function ReportPreview({ report }: { report?: Report }) {
  if (!report) return null
  return (
    <Card>
      <CardHeader>
        <CardTitle>{report.title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {report.executive_summary && (
          <>
            <p className="leading-relaxed">{report.executive_summary.overview}</p>
            <p className="text-text-muted">
              Risk rating: <span className="text-text font-medium">
                {report.executive_summary.risk_rating}
              </span>
            </p>
            {report.executive_summary.key_findings?.length > 0 && (
              <div>
                <div className="font-medium mb-1">Key findings</div>
                <ul className="list-disc list-inside space-y-0.5 text-text-muted">
                  {report.executive_summary.key_findings.map((s, i) =>
                    <li key={i}>{s}</li>)}
                </ul>
              </div>
            )}
          </>
        )}
        <div className="grid grid-cols-3 gap-2 pt-3 border-t border-line/30">
          <Stat label="Total"        value={report.statistics.total_findings} />
          <Stat label="Modules run"  value={report.statistics.modules_run} />
          <Stat label="Duration (s)" value={report.statistics.scan_duration} />
        </div>
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
