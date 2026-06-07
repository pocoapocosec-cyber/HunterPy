import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import type { ModuleStatus } from '@app-types/scan'

export function ModulePerformanceChart({ modules }: { modules: ModuleStatus[] }) {
  if (!modules?.length) return null
  const maxCount = Math.max(1, ...modules.map((m) => m.findings_count))
  return (
    <Card>
      <CardHeader><CardTitle>Findings per module</CardTitle></CardHeader>
      <CardContent>
        <ul className="space-y-2">
          {modules.map((m) => (
            <li key={m.name} className="text-sm">
              <div className="flex justify-between mb-1">
                <span className="font-medium">{m.name}</span>
                <span className="text-text-muted">{m.findings_count}</span>
              </div>
              <div className="h-2 bg-line/30 rounded overflow-hidden">
                <div className="h-full bg-brand"
                     style={{ width: `${(m.findings_count / maxCount) * 100}%` }} />
              </div>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  )
}
