import { ScanConfigForm } from './components/ScanConfigForm'

export function NewScanFeature() {
  return (
    <div className="max-w-3xl mx-auto space-y-4">
      <div>
        <h1 className="text-2xl font-bold">New scan</h1>
        <p className="text-sm text-text-muted">
          Configure a target and pick a scan mode. The orchestrator will
          run the appropriate modules and stream progress in real time.
        </p>
      </div>
      <ScanConfigForm />
    </div>
  )
}
