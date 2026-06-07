import { Download } from 'lucide-react'
import { Button } from '@components/ui/button'
import { reportsAPI } from '@/lib/api/reports'
import type { ReportFormat } from '@app-types/report'

const FORMATS: ReportFormat[] = ['html', 'json', 'markdown', 'csv']

export function ReportExporter({ scanId }: { scanId: string }) {
  async function download(fmt: ReportFormat) {
    const url = await reportsAPI.downloadUrl(scanId, fmt)
    const a = document.createElement('a')
    a.href = url
    a.target = '_blank'
    a.rel = 'noopener'
    a.click()
  }
  return (
    <div className="flex gap-2 flex-wrap">
      {FORMATS.map((fmt) => (
        <Button key={fmt} size="sm" variant="outline" onClick={() => download(fmt)}>
          <Download className="h-3.5 w-3.5" /> {fmt.toUpperCase()}
        </Button>
      ))}
    </div>
  )
}
