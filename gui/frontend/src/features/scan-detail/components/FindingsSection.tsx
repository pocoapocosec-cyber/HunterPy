import { useState } from 'react'
import type { Finding } from '@app-types/finding'
import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'
import { FindingsTable } from '@components/findings/FindingsTable'
import { Dialog } from '@components/ui/dialog'
import { FindingDetail } from '@components/findings/FindingDetail'

export function FindingsSection({ findings }: { findings: Finding[] }) {
  const [active, setActive] = useState<Finding | null>(null)
  return (
    <>
      <Card>
        <CardHeader><CardTitle>Findings ({findings.length})</CardTitle></CardHeader>
        <CardContent>
          <FindingsTable findings={findings} onRowClick={setActive} />
        </CardContent>
      </Card>
      <Dialog open={!!active} onClose={() => setActive(null)}
              title={active?.title || 'Finding'}>
        {active && <FindingDetail finding={active} />}
      </Dialog>
    </>
  )
}
