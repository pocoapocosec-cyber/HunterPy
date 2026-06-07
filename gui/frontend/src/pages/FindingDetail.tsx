import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { findingsAPI } from '@/lib/api/findings'
import { LoadingSpinner } from '@components/common/LoadingSpinner'
import { Alert } from '@components/ui/alert'
import { FindingDetail as Detail } from '@components/findings/FindingDetail'

export function FindingDetail() {
  const { findingId = '' } = useParams()
  const { data, isLoading, isError } = useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => findingsAPI.get(findingId),
    enabled: !!findingId,
  })
  if (isLoading) return <LoadingSpinner />
  if (isError || !data) return <Alert tone="error">Finding not found.</Alert>
  return (
    <div className="max-w-4xl mx-auto space-y-4">
      <h1 className="text-2xl font-bold">Finding</h1>
      <Detail finding={data} />
    </div>
  )
}
