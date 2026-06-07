import { useQuery } from '@tanstack/react-query'
import { reportsAPI } from '@/lib/api/reports'

export function useReports() {
  return useQuery({
    queryKey: ['reports'],
    queryFn: () => reportsAPI.list(),
  })
}
