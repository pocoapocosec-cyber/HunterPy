export const SCAN_MODES = [
  { value: 'passive',  label: 'Passive (no intrusion)' },
  { value: 'quick',    label: 'Quick (5 modules)' },
  { value: 'standard', label: 'Standard (bug-bounty)' },
  { value: 'full',     label: 'Full (all modules)' },
  { value: 'stealth',  label: 'Stealth (low & slow)' },
  { value: 'custom',   label: 'Custom' },
] as const

export const ALL_MODULES = [
  // passive
  { id: 'fingerprint', label: 'Tech fingerprint', phase: 'recon' },
  { id: 'headers',     label: 'Security headers', phase: 'recon' },
  { id: 'ssl',         label: 'TLS / certificate', phase: 'recon' },
  { id: 'dns',         label: 'DNS enumeration', phase: 'recon' },
  { id: 'whois',       label: 'WHOIS lookup', phase: 'recon' },
  { id: 'surface',     label: 'Surface map', phase: 'recon' },
  { id: 'js',          label: 'JS analyzer', phase: 'recon' },
  { id: 'js_vulns',    label: 'JS package CVEs (OSV)', phase: 'recon' },
  { id: 'endpoints',   label: 'Endpoint crawler', phase: 'recon' },
  // active
  { id: 'nuclei',      label: 'Nuclei templates', phase: 'active' },
  { id: 'nikto',       label: 'Nikto', phase: 'active' },
  { id: 'gobuster',    label: 'Gobuster', phase: 'active' },
  { id: 'ffuf',        label: 'FFUF', phase: 'active' },
  { id: 'wfuzz',       label: 'WFuzz', phase: 'active' },
  // exploitation
  { id: 'sqlmap',      label: 'SQLMap', phase: 'exploit' },
  { id: 'cors',        label: 'CORS tester', phase: 'exploit' },
  // auth
  { id: 'hydra',       label: 'Hydra (auth)', phase: 'auth' },
  // hash
  { id: 'john',        label: 'John the Ripper', phase: 'hashes' },
  { id: 'hashcat',     label: 'Hashcat', phase: 'hashes' },
] as const

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const
export const TIER_ORDER = ['INTERESTING', 'COMMON', 'FALSE_ALARM'] as const
