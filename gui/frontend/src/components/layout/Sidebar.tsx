import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Activity, AlertOctagon, FileText, Settings, Plus } from 'lucide-react'
import { ROUTES } from '@/config/routes'
import { cn } from '@/lib/cn'
import { Button } from '@components/ui/button'

const ITEMS = [
  { to: ROUTES.dashboard, label: 'Dashboard', icon: LayoutDashboard },
  { to: ROUTES.scans,     label: 'Scans',     icon: Activity       },
  { to: ROUTES.findings,  label: 'Findings',  icon: AlertOctagon   },
  { to: ROUTES.reports,   label: 'Reports',   icon: FileText       },
  { to: ROUTES.settings,  label: 'Settings',  icon: Settings       },
]

export function Sidebar() {
  return (
    <aside className="hidden md:flex flex-col w-56 border-r border-line/40
                       bg-bg-soft/40 p-3 gap-1 shrink-0">
      <NavLink to={ROUTES.newScan} className="mb-3">
        <Button variant="primary" className="w-full">
          <Plus className="h-4 w-4" /> New scan
        </Button>
      </NavLink>
      {ITEMS.map(({ to, label, icon: Icon }) => (
        <NavLink key={to} to={to} end
          className={({ isActive }) =>
            cn('flex items-center gap-2 px-3 py-2 rounded-md text-sm',
              isActive ? 'bg-brand/20 text-brand' :
                          'text-text-muted hover:text-text hover:bg-line/20')
          }>
          <Icon className="h-4 w-4" />
          {label}
        </NavLink>
      ))}
    </aside>
  )
}
