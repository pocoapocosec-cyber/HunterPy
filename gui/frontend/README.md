# HunterPy Frontend

Web UI for the HunterPy security scanner.

- **Stack**: Vite + React 18 + TypeScript + Tailwind + React Query +
  React Hook Form + Zod + custom UI primitives (no Radix / shadcn / Recharts).
- **Runs standalone** in mock mode — no backend needed to see the full UI.
- Path aliases use **`@app-types/*`** (not `@types/*`) to avoid colliding
  with the `@types/*` npm namespace.

---

## Quick start

```bash
cd gui/frontend
cp .env.example .env       # default = mock mode
npm install
npm run dev                # http://localhost:5173
```

By default `VITE_USE_MOCKS=true` reads from `public/mock/*.json` and the
app works end-to-end (dashboard, scans, scan detail, findings, reports,
settings) without any backend.

### Wire to a real backend

1. Set `VITE_USE_MOCKS=false` in `.env`.
2. Set `VITE_API_BASE_URL` to your FastAPI host.
3. Implement the routes in `src/lib/api/endpoints.ts` server-side.

The expected REST surface is documented in that file. WebSocket channel
for live progress: `ws://<host>/ws/scans/<scan_id>`.

---

## Project layout

```
src/
├── main.tsx                  App entry — QueryClient + Router + Toasts
├── App.tsx                   Route table
├── pages/                    Thin page wrappers (re-export features)
├── features/                 Feature-based modules
│   ├── dashboard/
│   ├── scans/
│   ├── new-scan/             react-hook-form + zod validation
│   ├── scan-detail/          live progress, modules, target, logs
│   ├── findings/             table + filters + detail dialog
│   ├── reports/              list, viewer, generator
│   ├── settings/             local-only preferences
│   └── auth/                 mock login + AuthGuard
├── components/
│   ├── ui/                   button, card, input, dialog, tabs, …
│   ├── layout/               Header / Sidebar / MainLayout / Footer
│   ├── scan/                 ScanProgressCard / PhaseIndicator / ModuleList
│   ├── findings/             SeverityBadge / TierBadge / Table / PoCViewer /
│   │                         RemediationGuide / ExploitRunner / Detail
│   ├── charts/               Custom SVG: pie, timeline, attack-surface map
│   ├── target/               Tech / DNS / SSL / WAF cards
│   ├── reports/              Preview / Exporter / FormatToggle
│   └── common/               LoadingSpinner / Search / Filter / CodeBlock / …
├── lib/
│   ├── api/                  client, endpoints, scans, findings, reports,
│   │                         websocket, mock adapter
│   ├── hooks/                useDebounce, useLocalStorage, usePagination, …
│   └── utils/                formatters, validators, exporters, colors
├── types/                    Domain types (Scan, Finding, Report, Target)
└── styles/                   globals.css + themes.css (dark by default)
```

---

## Mock mode

When `VITE_USE_MOCKS=true`:

- All `scansAPI`, `findingsAPI`, `reportsAPI` calls read from
  `public/mock/*.json` instead of hitting the network.
- `useScanWebSocket` ticks a fake progress bar so the live-progress UI
  feels alive.
- The auth guard accepts any non-empty credentials at `/login`.

To get realistic data, drop your own HunterPy JSON reports into
`public/mock/findings.json` and `public/mock/scans.json` (matching the
schemas in `src/types/`).

---

## Tailwind theme

Dark by default. The custom palette lives in `tailwind.config.js`:

| Token              | Color    | Use                                    |
|--------------------|----------|----------------------------------------|
| `bg`               | `#0f172a`| Page background                        |
| `bg-soft`          | `#1e293b`| Cards / panels                         |
| `bg-deep`          | `#0b1220`| Code blocks / inputs                   |
| `brand`            | `#06b6d4`| Buttons, focus rings, accents          |
| `severity-critical`| `#dc2626`|                                        |
| `severity-high`    | `#ea580c`|                                        |
| `severity-medium`  | `#d97706`|                                        |
| `severity-low`     | `#16a34a`|                                        |
| `tier-interesting` | `#dc2626`|                                        |
| `tier-common`      | `#d97706`|                                        |
| `tier-falsealarm`  | `#16a34a`|                                        |

---

## Scripts

```bash
npm run dev          # vite dev server (port 5173)
npm run build        # type-check + production build → dist/
npm run preview      # serve the built bundle locally
npm run lint         # eslint
npm run type-check   # tsc --noEmit
```

---

## Known limitations

- No live backend yet — the next step is a FastAPI layer that wraps the
  existing `ScannerEngine` and exposes the routes in `endpoints.ts`.
- The "exploit runner" UI only works in mock mode (returns canned text).
  Wiring it to a real exploit module needs explicit per-finding
  authorization gates server-side.
- No tests yet — the React side ships without a Vitest setup; the
  Python core has 96 unit tests of its own.
