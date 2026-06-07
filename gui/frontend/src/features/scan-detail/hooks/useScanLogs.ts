import { useQuery } from '@tanstack/react-query'
import { scansAPI } from '@/lib/api/scans'

export function useScanLogs(scanId: string) {
  return useQuery({
    queryKey: ['scan-logs', scanId],
    queryFn: () => scansAPI.getLogs(scanId),
    refetchInterval: 4_000,
    enabled: !!scanId,
  })
}
