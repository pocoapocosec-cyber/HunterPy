import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Plus } from 'lucide-react'
import { Button } from '@components/ui/button'
import { LoadingSpinner } from '@components/common/LoadingSpinner'
import { ScanFilters } from './components/ScanFilters'
import { ScanList } from './components/ScanList'
import { useScans } from './hooks/useScans'
import { ROUTES } from '@/config/routes'
import type { ScanStatus } from '@app-types/scan'

export function ScansFeature() {
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState<string>('')
  const { data, isLoading } = useScans({
    status: (status || undefined) as ScanStatus | undefined,
    limit: 100,
  })

  const filtered = useMemo(() => {
    const list = data?.scans || []
    if (!search.trim()) return list
    const q = search.toLowerCase()
    return list.filter((s) => s.target.toLowerCase().includes(q))
  }, [data, search])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scans</h1>
          <p className="text-sm text-text-muted">{filtered.length} scan(s)</p>
        </div>
        <Link to={ROUTES.newScan}>
          <Button variant="primary"><Plus className="h-4 w-4" /> New scan</Button>
        </Link>
      </div>

      <ScanFilters search={search} onSearch={setSearch}
                   status={status} onStatus={setStatus} />

      {isLoading ? <LoadingSpinner /> : <ScanList scans={filtered} />}
    </div>
  )
}
