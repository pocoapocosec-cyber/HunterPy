import { FilterDropdown } from '@components/common/FilterDropdown'
import { SearchBar } from '@components/common/SearchBar'

export interface FindingFiltersProps {
  search: string
  severity: string
  tier: string
  onSearch: (s: string) => void
  onSeverity: (s: string) => void
  onTier: (s: string) => void
}
export function FindingFilters(p: FindingFiltersProps) {
  return (
    <div className="flex gap-2 flex-wrap">
      <SearchBar value={p.search} onChange={p.onSearch}
                 placeholder="Search findings…" className="max-w-xs" />
      <FilterDropdown label="severity" value={p.severity} onChange={p.onSeverity}
        options={[
          { value: 'critical', label: 'Critical' },
          { value: 'high',     label: 'High' },
          { value: 'medium',   label: 'Medium' },
          { value: 'low',      label: 'Low' },
          { value: 'info',     label: 'Info' },
        ]}
      />
      <FilterDropdown label="tier" value={p.tier} onChange={p.onTier}
        options={[
          { value: 'INTERESTING', label: 'Interesting' },
          { value: 'COMMON',      label: 'Common' },
          { value: 'FALSE_ALARM', label: 'False alarm' },
        ]}
      />
    </div>
  )
}
