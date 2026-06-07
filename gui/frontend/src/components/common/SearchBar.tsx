import { Search } from 'lucide-react'
import { Input } from '@components/ui/input'

export interface SearchBarProps {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  className?: string
}
export function SearchBar({ value, onChange, placeholder, className }: SearchBarProps) {
  return (
    <div className={`relative ${className || ''}`}>
      <Search className="h-4 w-4 absolute left-2.5 top-2.5 text-text-muted" />
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder || 'Search…'}
        className="pl-9"
      />
    </div>
  )
}
