import type { Scan } from '@app-types/scan'
import { ScanCard } from './ScanCard'
import { EmptyState } from '@components/common/EmptyState'

export function ScanList({ scans }: { scans: Scan[] }) {
  if (!scans.length) {
    return <EmptyState title="No scans"
                       description="Start one to see it appear here." />
  }
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
      {scans.map((s) => <ScanCard key={s.id} scan={s} />)}
    </div>
  )
}
