import { GeneralSettings } from './components/GeneralSettings'
import { ScanDefaults } from './components/ScanDefaults'
import { APIKeys } from './components/APIKeys'
import { NotificationSettings } from './components/NotificationSettings'
import { ToolPaths } from './components/ToolPaths'

export function SettingsFeature() {
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Settings</h1>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <GeneralSettings />
        <ScanDefaults />
        <APIKeys />
        <NotificationSettings />
        <div className="lg:col-span-2"><ToolPaths /></div>
      </div>
    </div>
  )
}
