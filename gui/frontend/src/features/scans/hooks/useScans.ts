import { useQuery } from '@tanstack/react-query'
import { scansAPI, type ScanListParams } from '@/lib/api/scans'

export function useScans(params?: ScanListParams) {
  return useQuery({
    queryKey: ['scans', params],
    queryFn: () => scansAPI.list(params),
    refetchInterval: 5_000,
  })
}
