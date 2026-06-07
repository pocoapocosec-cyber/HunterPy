import { Filter } from 'lucide-react'
import { Button } from '@components/ui/button'
import { DropdownMenu, DropdownItem } from '@components/ui/dropdown-menu'

export interface FilterOption { value: string; label: string }
export interface FilterDropdownProps {
  label: string
  options: FilterOption[]
  value?: string
  onChange: (v: string) => void
}
export function FilterDropdown({ label, options, value, onChange }: FilterDropdownProps) {
  const current = options.find((o) => o.value === value)?.label
  return (
    <DropdownMenu trigger={
      <Button variant="outline" size="sm">
        <Filter className="h-3.5 w-3.5" />
        {label}: <span className="font-medium">{current || 'all'}</span>
      </Button>
    }>
      <DropdownItem onClick={() => onChange('')}>All</DropdownItem>
      {options.map((o) => (
        <DropdownItem key={o.value} onClick={() => onChange(o.value)}>
          {o.label}
        </DropdownItem>
      ))}
    </DropdownMenu>
  )
}
