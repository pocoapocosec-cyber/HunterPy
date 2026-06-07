import { Link } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { Badge } from '@components/ui/badge'
import type { Scan } from '@app-types/scan'
import { formatRelative } from '@/lib/utils/formatters'
import { ROUTES } from '@/config/routes'
import { EmptyState } from '@components/common/EmptyState'

export function RecentScans({ scans }: { scans: Scan[] }) {
  return (
    <Card>
      <CardHeader><CardTitle>Recent scans</CardTitle></CardHeader>
      <CardContent>
        {scans.length === 0 ? (
          <EmptyState title="No scans yet"
                      description="Start a new scan from the sidebar." />
        ) : (
          <ul className="divide-y divide-line/20">
            {scans.map((s) => (
              <li key={s.id}>
                <Link to={ROUTES.scanDetail(s.id)}
                      className="flex items-center justify-between py-2 hover:bg-line/15
                                 -mx-2 px-2 rounded">
                  <div>
                    <div className="font-medium text-sm">{s.target}</div>
                    <div className="text-xs text-text-muted">
                      {s.mode} · {formatRelative(s.created_at)}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={
                      s.status === 'running' ? 'warn'
                        : s.status === 'completed' ? 'success'
                        : s.status === 'failed' ? 'danger' : 'default'
                    }>{s.status}</Badge>
                    <span className="text-xs text-text-muted">
                      {s.findings_count} findings
                    </span>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
