import type { Finding } from '@app-types/finding'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { SeverityBadge } from './SeverityBadge'
import { TierBadge } from './TierBadge'
import { POCViewer } from './POCViewer'
import { RemediationGuide } from './RemediationGuide'
import { ExploitRunner } from './ExploitRunner'
import { Tabs } from '@components/ui/tabs'
import { CodeBlock } from '@components/common/CodeBlock'

export function FindingDetail({ finding }: { finding: Finding }) {
  const evidenceJson = finding.evidence
    ? JSON.stringify(finding.evidence, null, 2)
    : ''

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={finding.severity} />
            <TierBadge tier={finding.classification || finding.tier} />
            {finding.cvss != null && (
              <span className="text-xs text-text-muted">
                CVSS {finding.cvss.toFixed(1)}
              </span>
            )}
            {finding.module && (
              <span className="text-xs text-text-muted ml-auto">{finding.module}</span>
            )}
          </div>
          <CardTitle className="mt-2">{finding.title}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {finding.description && (
            <p className="text-sm leading-relaxed">{finding.description}</p>
          )}
          {finding.url && (
            <div className="text-xs">
              <span className="text-text-muted">URL: </span>
              <a className="text-brand hover:underline break-all" href={finding.url}
                 target="_blank" rel="noopener noreferrer">{finding.url}</a>
            </div>
          )}
          {finding.classification_reason && (
            <div className="text-xs text-text-muted">
              Reasoning: {finding.classification_reason}
              {finding.classification_confidence != null &&
                ` (confidence ${(finding.classification_confidence * 100).toFixed(0)}%)`}
            </div>
          )}
        </CardContent>
      </Card>

      <Tabs items={[
        { id: 'poc',     label: 'Proof of concept',
          content: <POCViewer poc={finding.poc} /> },
        { id: 'remed',   label: 'Remediation',
          content: <RemediationGuide finding={finding} /> },
        { id: 'evidence', label: 'Evidence',
          content: evidenceJson
            ? <CodeBlock code={evidenceJson} language="json" />
            : <div className="text-sm text-text-muted">No evidence captured.</div> },
        { id: 'exploit', label: 'Exploit',
          content: <ExploitRunner findingId={finding.id} /> },
      ]} />
    </div>
  )
}
