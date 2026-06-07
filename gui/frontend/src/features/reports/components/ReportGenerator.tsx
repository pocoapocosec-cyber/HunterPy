import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Button } from '@components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { Input } from '@components/ui/input'
import { ReportFormatToggle } from '@components/reports/ReportFormatToggle'
import { reportsAPI } from '@/lib/api/reports'
import { useToast } from '@components/ui/toast'
import type { ReportFormat } from '@app-types/report'

export function ReportGenerator() {
  const [scanId, setScanId] = useState('')
  const [format, setFormat] = useState<ReportFormat>('html')
  const toast = useToast()

  const gen = useMutation({
    mutationFn: () => reportsAPI.generate(scanId, format),
    onSuccess: () => toast.push('Report generated', 'success'),
    onError: (e: any) => toast.push(e?.message || 'Failed', 'error'),
  })

  return (
    <Card>
      <CardHeader><CardTitle>Generate report</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <div>
          <label className="block text-sm mb-1">Scan ID</label>
          <Input placeholder="scan_…" value={scanId}
                 onChange={(e) => setScanId(e.target.value)} />
        </div>
        <div>
          <label className="block text-sm mb-1">Format</label>
          <ReportFormatToggle value={format} onChange={setFormat} />
        </div>
        <Button variant="primary" disabled={!scanId} isLoading={gen.isPending}
                onClick={() => gen.mutate()}>
          Generate
        </Button>
      </CardContent>
    </Card>
  )
}
