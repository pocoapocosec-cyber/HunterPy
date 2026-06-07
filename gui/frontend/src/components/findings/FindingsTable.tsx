import { useMemo, useState } from 'react'
import { ExternalLink, ArrowUpDown } from 'lucide-react'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow }
  from '@components/ui/table'
import { SearchBar } from '@components/common/SearchBar'
import { SeverityBadge } from './SeverityBadge'
import { TierBadge } from './TierBadge'
import type { Finding } from '@app-types/finding'
import { formatRelative, truncate } from '@/lib/utils/formatters'
import { Button } from '@components/ui/button'
import { usePagination } from '@/lib/hooks/usePagination'

export interface FindingsTableProps {
  findings: Finding[]
  onRowClick?: (f: Finding) => void
}

type SortKey = 'severity' | 'tier' | 'title' | 'score'
const SEV_ORDER: Record<string, number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1,
}
const TIER_ORDER: Record<string, number> = {
  INTERESTING: 3, COMMON: 2, FALSE_ALARM: 1,
}

export function FindingsTable({ findings, onRowClick }: FindingsTableProps) {
  const [q, setQ] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('score')
  const [sortDir, setSortDir] = useState<1 | -1>(-1)

  const filtered = useMemo(() => {
    const ql = q.trim().toLowerCase()
    let list = !ql ? findings : findings.filter((f) =>
      (f.title + ' ' + (f.url || '') + ' ' + (f.module || '') + ' ' +
       (f.description || '')).toLowerCase().includes(ql))

    const cmp = (a: Finding, b: Finding) => {
      let av: number | string = 0, bv: number | string = 0
      switch (sortKey) {
        case 'severity':
          av = SEV_ORDER[(a.severity || 'info').toUpperCase()] || 0
          bv = SEV_ORDER[(b.severity || 'info').toUpperCase()] || 0
          break
        case 'tier':
          av = TIER_ORDER[(a.classification || a.tier || 'COMMON').toUpperCase()] || 0
          bv = TIER_ORDER[(b.classification || b.tier || 'COMMON').toUpperCase()] || 0
          break
        case 'title':
          av = a.title?.toLowerCase() || ''
          bv = b.title?.toLowerCase() || ''
          break
        case 'score':
        default:
          av = a.score || a.cvss || 0
          bv = b.score || b.cvss || 0
      }
      if (av < bv) return -1 * sortDir
      if (av > bv) return  1 * sortDir
      return 0
    }
    return [...list].sort(cmp)
  }, [findings, q, sortKey, sortDir])

  const pager = usePagination(filtered, 20)

  function toggleSort(k: SortKey) {
    if (sortKey === k) setSortDir((d) => (d === 1 ? -1 : 1))
    else { setSortKey(k); setSortDir(k === 'title' ? 1 : -1) }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <SearchBar value={q} onChange={setQ}
                   placeholder="Search findings…" className="max-w-sm" />
        <div className="text-xs text-text-muted">
          {filtered.length} of {findings.length}
        </div>
      </div>

      <div className="rounded-md border border-line/40 overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <SortHead label="Severity" onClick={() => toggleSort('severity')} />
              <SortHead label="Tier"     onClick={() => toggleSort('tier')} />
              <SortHead label="Score"    onClick={() => toggleSort('score')} />
              <SortHead label="Finding"  onClick={() => toggleSort('title')} />
              <TableHead>Module</TableHead>
              <TableHead>URL</TableHead>
              <TableHead>Discovered</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {pager.slice.map((f) => (
              <TableRow key={f.id} className="cursor-pointer"
                        onClick={() => onRowClick?.(f)}>
                <TableCell><SeverityBadge severity={f.severity} /></TableCell>
                <TableCell><TierBadge tier={f.classification || f.tier} /></TableCell>
                <TableCell className="font-mono text-xs">
                  {(f.score || f.cvss || 0).toFixed(1)}
                </TableCell>
                <TableCell className="max-w-md">
                  <div className="font-medium">{truncate(f.title, 80)}</div>
                  {f.description && (
                    <div className="text-xs text-text-muted">
                      {truncate(f.description, 120)}
                    </div>
                  )}
                </TableCell>
                <TableCell className="text-xs text-text-muted">{f.module}</TableCell>
                <TableCell>
                  {f.url ? (
                    <a href={f.url} target="_blank" rel="noopener noreferrer"
                       className="inline-flex items-center gap-1 text-brand hover:underline text-xs"
                       onClick={(e) => e.stopPropagation()}>
                      {truncate(f.url, 40)}
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  ) : '—'}
                </TableCell>
                <TableCell className="text-xs text-text-muted whitespace-nowrap">
                  {formatRelative(f.discovered_at || f.created_at)}
                </TableCell>
              </TableRow>
            ))}
            {pager.slice.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-10 text-text-muted">
                  No findings match the filters.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-between">
        <div className="text-xs text-text-muted">
          Page {pager.page + 1} / {pager.pageCount}
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={pager.prev}
                  disabled={pager.page === 0}>Previous</Button>
          <Button size="sm" variant="outline" onClick={pager.next}
                  disabled={pager.page >= pager.pageCount - 1}>Next</Button>
        </div>
      </div>
    </div>
  )
}

function SortHead({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <TableHead>
      <button onClick={onClick}
              className="inline-flex items-center gap-1 hover:text-text">
        {label} <ArrowUpDown className="h-3 w-3" />
      </button>
    </TableHead>
  )
}
