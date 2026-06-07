import { useScanWebSocket } from '@/lib/api/websocket'
import { ScanProgressCard } from '@components/scan/ScanProgressCard'

export function LiveProgress({ scanId }: { scanId: string }) {
  const { progress, findings } = useScanWebSocket(scanId)
  return <ScanProgressCard progress={progress} findingsCount={findings.length} />
}
