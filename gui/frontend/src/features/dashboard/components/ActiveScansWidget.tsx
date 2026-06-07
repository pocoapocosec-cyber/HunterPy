import { useQuery } from '@tanstack/react-query'
import { scansAPI } from '@/lib/api/scans'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { Progress } from '@components/ui/progress'
import { EmptyState } from '@components/common/EmptyState'
import { Link } from 'react-router-dom'
import { ROUTES } from '@/config/routes'

export function ActiveScansWidget() {
  const { data } = useQuery({
    queryKey: ['active-scans'],
    queryFn: () => scansAPI.list({ status: 'running' }),
    refetchInterval: 4_000,
  })
  const list = data?.scans || []
  return (
    <Card>
      <CardHeader><CardTitle>Active scans</CardTitle></CardHeader>
      <CardContent>
        {list.length === 0 ? (
          <EmptyState title="Nothing running" description="All scans are idle." />
        ) : (
          <ul className="space-y-3">
            {list.map((s) => (
              <li key={s.id}>
                <Link to={ROUTES.scanDetail(s.id)} className="block group">
                  <div className="flex justify-between text-sm mb-1">
                    <span className="font-medium group-hover:text-brand">
                      {s.target}
                    </span>
                    <span className="text-text-muted">{s.progress || 0}%</span>
                  </div>
                  <Progress value={s.progress || 0} />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
