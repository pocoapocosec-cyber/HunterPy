import { FilterDropdown } from '@components/common/FilterDropdown'
import { SearchBar } from '@components/common/SearchBar'

export interface ScanFiltersProps {
  search: string
  status: string
  onSearch: (s: string) => void
  onStatus: (s: string) => void
}
export function ScanFilters({ search, status, onSearch, onStatus }: ScanFiltersProps) {
  return (
    <div className="flex gap-2 flex-wrap">
      <SearchBar value={search} onChange={onSearch}
                 placeholder="Search by target…" className="max-w-xs" />
      <FilterDropdown label="status" value={status} onChange={onStatus}
        options={[
          { value: 'running',   label: 'Running' },
          { value: 'completed', label: 'Completed' },
          { value: 'failed',    label: 'Failed' },
          { value: 'paused',    label: 'Paused' },
        ]}
      />
    </div>
  )
}
