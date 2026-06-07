import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api/client'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { ENDPOINTS } from '@/lib/api/endpoints'
import { Badge } from '@components/ui/badge'

interface ToolInfo { name: string; available: boolean; version?: string; required?: boolean }

export function ToolPaths() {
  const { data, isLoading } = useQuery({
    queryKey: ['tools'],
    queryFn: async () => {
      if (apiClient.useMocks) {
        return [
          { name: 'nmap',     available: false, required: false },
          { name: 'nikto',    available: false, required: true  },
          { name: 'sqlmap',   available: false, required: true  },
          { name: 'gobuster', available: false, required: true  },
          { name: 'ffuf',     available: false, required: true  },
          { name: 'nuclei',   available: false, required: false },
          { name: 'curl',     available: true, version: 'curl 8.x', required: false },
        ] as ToolInfo[]
      }
      return apiClient.get<ToolInfo[]>(ENDPOINTS.tools)
    },
  })
  return (
    <Card>
      <CardHeader><CardTitle>External tools</CardTitle></CardHeader>
      <CardContent>
        {isLoading
          ? <div className="text-sm text-text-muted">Checking…</div>
          : (
            <ul className="text-sm divide-y divide-line/20">
              {(data || []).map((t) => (
                <li key={t.name} className="flex justify-between py-2">
                  <span>
                    {t.name} {t.required && <span className="text-text-muted">(required)</span>}
                  </span>
                  {t.available
                    ? <Badge variant="success">{t.version || 'ok'}</Badge>
                    : <Badge variant="default">missing</Badge>}
                </li>
              ))}
            </ul>
          )}
      </CardContent>
    </Card>
  )
}
