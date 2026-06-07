import { Select } from '@components/ui/select'
import type { ReportTemplate } from '@app-types/report'

export function ReportTemplateSelector({ templates, value, onChange }:
  { templates: ReportTemplate[]; value?: string; onChange: (id: string) => void }) {
  return (
    <Select value={value || ''} onChange={(e) => onChange(e.target.value)}>
      <option value="">Default template</option>
      {templates.map((t) => (
        <option key={t.id} value={t.id}>{t.name}</option>
      ))}
    </Select>
  )
}
