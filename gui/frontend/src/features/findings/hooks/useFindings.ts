import { useQuery } from '@tanstack/react-query'
import { findingsAPI, type FindingListParams } from '@/lib/api/findings'

export function useFindings(params?: FindingListParams) {
  return useQuery({
    queryKey: ['findings', params],
    queryFn: () => findingsAPI.list(params),
    refetchInterval: 10_000,
  })
}
