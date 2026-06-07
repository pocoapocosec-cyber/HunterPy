import type { ProofOfConcept } from '@app-types/finding'
import { CodeBlock } from '@components/common/CodeBlock'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'

export function POCViewer({ poc }: { poc?: ProofOfConcept }) {
  if (!poc) return (
    <div className="text-sm text-text-muted">
      No proof-of-concept available for this finding.
    </div>
  )
  return (
    <Card>
      <CardHeader><CardTitle>Verification</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm">{poc.description}</p>

        {poc.steps?.length > 0 && (
          <ol className="list-decimal list-inside text-sm space-y-1 text-text">
            {poc.steps.map((s, i) => <li key={i}>{s}</li>)}
          </ol>
        )}

        {poc.sample_command && (
          <CodeBlock code={poc.sample_command} language="bash" />
        )}

        {poc.references?.length > 0 && (
          <div className="pt-2 border-t border-line/30">
            <div className="text-xs text-text-muted mb-1">References</div>
            <ul className="text-xs space-y-1">
              {poc.references.map((r, i) => (
                <li key={i}>
                  <a className="text-brand hover:underline break-all"
                     href={r} target="_blank" rel="noopener noreferrer">{r}</a>
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
