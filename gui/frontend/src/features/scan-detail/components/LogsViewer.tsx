import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { useScanLogs } from '../hooks/useScanLogs'

export function LogsViewer({ scanId }: { scanId: string }) {
  const { data } = useScanLogs(scanId)
  const logs = data?.logs || []
  return (
    <Card>
      <CardHeader><CardTitle>Logs</CardTitle></CardHeader>
      <CardContent>
        <pre className="bg-bg-deep border border-line/30 rounded p-3 text-xs
                        overflow-auto max-h-96 leading-relaxed">
{logs.length === 0 ? '(no logs yet)' : logs.join('\n')}
        </pre>
      </CardContent>
    </Card>
  )
}
