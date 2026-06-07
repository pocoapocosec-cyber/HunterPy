import { Card, CardContent } from '@components/ui/card'
import { SeverityBadge } from './SeverityBadge'
import { TierBadge } from './TierBadge'
import type { Finding } from '@app-types/finding'
import { cn } from '@/lib/cn'

export interface FindingCardProps {
  finding: Finding
  onClick?: () => void
  className?: string
}
export function FindingCard({ finding, onClick, className }: FindingCardProps) {
  return (
    <Card className={cn('hover:border-brand/40 transition-colors cursor-pointer',
                        className)}
          onClick={onClick}>
      <CardContent className="space-y-2">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <TierBadge tier={finding.classification || finding.tier} />
          <span className="text-xs text-text-muted ml-auto">{finding.module}</span>
        </div>
        <div className="font-medium">{finding.title}</div>
        {finding.description && (
          <p className="text-sm text-text-muted line-clamp-2">{finding.description}</p>
        )}
        {finding.url && (
          <div className="text-xs font-mono text-brand truncate">{finding.url}</div>
        )}
      </CardContent>
    </Card>
  )
}
