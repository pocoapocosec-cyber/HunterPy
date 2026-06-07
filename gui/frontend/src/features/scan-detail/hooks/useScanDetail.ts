import { useQuery } from '@tanstack/react-query'
import { scansAPI } from '@/lib/api/scans'
import { findingsAPI } from '@/lib/api/findings'

export function useScanDetail(scanId: string) {
  const scan = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansAPI.get(scanId),
    refetchInterval: 5_000,
    enabled: !!scanId,
  })
  const findings = useQuery({
    queryKey: ['scan-findings', scanId],
    queryFn: () => findingsAPI.listByScan(scanId, { limit: 1000 }),
    refetchInterval: 10_000,
    enabled: !!scanId,
  })
  const modules = useQuery({
    queryKey: ['scan-modules', scanId],
    queryFn: () => scansAPI.getModules(scanId),
    refetchInterval: 5_000,
    enabled: !!scanId,
  })
  const target = useQuery({
    queryKey: ['scan-target', scanId],
    queryFn: () => scansAPI.getTarget(scanId),
    enabled: !!scanId,
  })
  return { scan, findings, modules, target }
}
