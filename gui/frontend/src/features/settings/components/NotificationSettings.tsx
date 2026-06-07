import { Card, CardContent, CardHeader, CardTitle } from '@components/ui/card'

export function NotificationSettings() {
  return (
    <Card>
      <CardHeader><CardTitle>Notifications</CardTitle></CardHeader>
      <CardContent className="text-sm text-text-muted">
        Slack / Discord / webhook integrations will land here. For now, in-app
        toasts via the General settings panel.
      </CardContent>
    </Card>
  )
}
