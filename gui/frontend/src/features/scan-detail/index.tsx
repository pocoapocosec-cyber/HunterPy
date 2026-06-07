import { useParams } from 'react-router-dom'
import { LoadingSpinner } from '@components/common/LoadingSpinner'
import { Alert } from '@components/ui/alert'
import { Tabs } from '@components/ui/tabs'
import { ModuleStatusList } from '@components/scan/ModuleStatusList'
import { useScanDetail } from './hooks/useScanDetail'
import { ScanOverview } from './components/ScanOverview'
import { LiveProgress } from './components/LiveProgress'
import { FindingsSection } from './components/FindingsSection'
import { TargetSection } from './components/TargetSection'
import { LogsViewer } from './components/LogsViewer'
import { ActionButtons } from './components/ActionButtons'
import { ReportExporter } from '@components/reports/ReportExporter'

export function ScanDetailFeature() {
  const { scanId = '' } = useParams()
  const { scan, findings, modules, target } = useScanDetail(scanId)

  if (scan.isLoading) return <LoadingSpinner />
  if (scan.isError || !scan.data)
    return <Alert tone="error">Could not load scan {scanId}.</Alert>

  const fList = findings.data?.findings || []

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Scan detail</h1>
        <ActionButtons scan={scan.data} />
      </div>

      <ScanOverview scan={scan.data} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <LiveProgress scanId={scanId} />
        </div>
        <div className="space-y-4">
          <ReportExporter scanId={scanId} />
          <ModuleStatusList modules={modules.data || []} />
        </div>
      </div>

      <Tabs items={[
        { id: 'findings', label: `Findings (${fList.length})`,
          content: <FindingsSection findings={fList} /> },
        { id: 'target', label: 'Target',
          content: target.data
            ? <TargetSection target={target.data} />
            : <LoadingSpinner /> },
        { id: 'logs', label: 'Logs',
          content: <LogsViewer scanId={scanId} /> },
      ]} />
    </div>
  )
}
