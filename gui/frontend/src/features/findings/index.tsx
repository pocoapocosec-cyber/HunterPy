import { AllFindings } from './components/AllFindings'

export function FindingsFeature() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold">Findings</h1>
        <p className="text-sm text-text-muted">
          Aggregated across all scans. Click a row to see PoC, remediation,
          and exploit options.
        </p>
      </div>
      <AllFindings />
    </div>
  )
}
