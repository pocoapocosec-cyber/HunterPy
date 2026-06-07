import { Link, NavLink } from 'react-router-dom'
import { ShieldCheck, Search, Bell } from 'lucide-react'
import { ROUTES } from '@/config/routes'
import { Input } from '@components/ui/input'
import { cn } from '@/lib/cn'

const NAV = [
  { to: ROUTES.dashboard, label: 'Dashboard' },
  { to: ROUTES.scans,     label: 'Scans' },
  { to: ROUTES.findings,  label: 'Findings' },
  { to: ROUTES.reports,   label: 'Reports' },
  { to: ROUTES.settings,  label: 'Settings' },
]

export function Header() {
  return (
    <header className="h-14 border-b border-line/40 bg-bg-soft/80 backdrop-blur
                       sticky top-0 z-30">
      <div className="h-full px-4 flex items-center gap-6">
        <Link to={ROUTES.dashboard} className="flex items-center gap-2 font-semibold">
          <ShieldCheck className="h-5 w-5 text-brand" />
          <span>HunterPy</span>
          <span className="text-xs text-text-muted ml-1">v2.0</span>
        </Link>

        <nav className="hidden md:flex items-center gap-1 ml-4">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end
              className={({ isActive }) =>
                cn('px-3 py-1.5 rounded-md text-sm transition-colors',
                  isActive ? 'bg-line/30 text-text' :
                              'text-text-muted hover:text-text hover:bg-line/20')
              }>{n.label}</NavLink>
          ))}
        </nav>

        <div className="flex-1 max-w-md ml-auto">
          <div className="relative">
            <Search className="h-4 w-4 absolute left-2.5 top-2.5 text-text-muted" />
            <Input placeholder="Search findings, scans, targets…"
                   className="pl-9" />
          </div>
        </div>

        <button className="relative p-2 rounded-md hover:bg-line/30" aria-label="Notifications">
          <Bell className="h-4 w-4" />
        </button>
      </div>
    </header>
  )
}
