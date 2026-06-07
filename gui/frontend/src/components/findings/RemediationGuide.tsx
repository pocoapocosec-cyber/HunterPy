import type { Finding, Remediation } from '@app-types/finding'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { CodeBlock } from '@components/common/CodeBlock'

export function RemediationGuide({ finding }: { finding: Finding }) {
  const r = finding.remediation
  if (!r) return null

  if (typeof r === 'string') {
    return (
      <Card>
        <CardHeader><CardTitle>Remediation</CardTitle></CardHeader>
        <CardContent><p className="text-sm">{r}</p></CardContent>
      </Card>
    )
  }
  const rem = r as Remediation
  return (
    <Card>
      <CardHeader><CardTitle>Remediation</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm">{rem.summary}</p>
        {rem.detailed_steps?.length > 0 && (
          <ol className="list-decimal list-inside text-sm space-y-1">
            {rem.detailed_steps.map((s, i) => <li key={i}>{s}</li>)}
          </ol>
        )}
        {rem.code_example && (
          <CodeBlock code={rem.code_example} language="text" />
        )}
        <div className="text-xs text-text-muted">
          Difficulty: <span className="text-text">{rem.difficulty}</span>
          {rem.estimated_time && (
            <> · Est. time: <span className="text-text">{rem.estimated_time}</span></>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
