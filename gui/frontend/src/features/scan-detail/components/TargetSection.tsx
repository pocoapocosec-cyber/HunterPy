import type { TargetInfo } from '@app-types/target'
import { TargetInfo as TargetInfoCard } from '@components/target/TargetInfo'
import { TechStackDisplay } from '@components/target/TechStackDisplay'
import { DNSRecords } from '@components/target/DNSRecords'
import { SSLCertInfo } from '@components/target/SSLCertInfo'
import { WAFDetectionBadge } from '@components/target/WAFDetectionBadge'

export function TargetSection({ target }: { target: TargetInfo }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <WAFDetectionBadge waf={target.waf_detected} />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <TargetInfoCard target={target} />
        <TechStackDisplay stack={target.tech_stack} />
        <DNSRecords records={target.dns_records} />
        <SSLCertInfo ssl={target.ssl_info} />
      </div>
    </div>
  )
}
