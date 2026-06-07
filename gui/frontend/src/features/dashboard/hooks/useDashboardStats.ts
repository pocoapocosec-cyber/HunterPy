import { useQuery } from '@tanstack/react-query'
import { scansAPI } from '@/lib/api/scans'
import { findingsAPI } from '@/lib/api/findings'

export interface DashboardStats {
  total_scans: number
  active_scans: number
  total_findings: number
  critical_findings: number
  high_findings: number
  interesting_findings: number
}

export function useDashboardStats() {
  return useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: async (): Promise<DashboardStats> => {
      const [scans, findings] = await Promise.all([
        scansAPI.list({ limit: 200 }),
        findingsAPI.list({ limit: 2000 }),
      ])
      const f = findings.findings
      return {
        total_scans: scans.total,
        active_scans: scans.scans.filter((s) => s.status === 'running').length,
        total_findings: findings.total,
        critical_findings: f.filter((x) => x.severity === 'critical').length,
        high_findings:     f.filter((x) => x.severity === 'high').length,
        interesting_findings:
          f.filter((x) => (x.classification || x.tier) === 'INTERESTING').length,
      }
    },
    refetchInterval: 10_000,
  })
}
