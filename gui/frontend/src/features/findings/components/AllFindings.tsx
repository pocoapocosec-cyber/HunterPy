import { useMemo, useState } from 'react'
import { LoadingSpinner } from '@components/common/LoadingSpinner'
import { FindingsTable } from '@components/findings/FindingsTable'
import { FindingFilters } from './FindingFilters'
import { FindingStats } from './FindingStats'
import { useFindings } from '../hooks/useFindings'
import { Dialog } from '@components/ui/dialog'
import { FindingDetail } from '@components/findings/FindingDetail'
import type { Finding } from '@app-types/finding'

export function AllFindings() {
  const { data, isLoading } = useFindings({ limit: 1000 })
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [tier, setTier] = useState('')
  const [active, setActive] = useState<Finding | null>(null)

  const filtered = useMemo(() => {
    let list = data?.findings || []
    const q = search.trim().toLowerCase()
    if (q) list = list.filter((f) =>
      (f.title + ' ' + (f.url || '') + ' ' + (f.module || '')).toLowerCase().includes(q))
    if (severity) list = list.filter((f) => f.severity === severity)
    if (tier)     list = list.filter((f) => (f.classification || f.tier) === tier)
    return list
  }, [data, search, severity, tier])

  if (isLoading) return <LoadingSpinner />

  return (
    <div className="space-y-4">
      <FindingStats findings={filtered} />
      <FindingFilters
        search={search}     onSearch={setSearch}
        severity={severity} onSeverity={setSeverity}
        tier={tier}         onTier={setTier}
      />
      <FindingsTable findings={filtered} onRowClick={setActive} />
      <Dialog open={!!active} onClose={() => setActive(null)}
              title={active?.title || ''}>
        {active && <FindingDetail finding={active} />}
      </Dialog>
    </div>
  )
}
