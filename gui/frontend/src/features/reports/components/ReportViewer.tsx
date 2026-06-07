import type { Report } from '@app-types/report'
import { ReportPreview } from '@components/reports/ReportPreview'
import { ReportExporter } from '@components/reports/ReportExporter'

export function ReportViewer({ report }: { report: Report }) {
  return (
    <div className="space-y-3">
      <ReportPreview report={report} />
      <ReportExporter scanId={report.scan_id} />
    </div>
  )
}
