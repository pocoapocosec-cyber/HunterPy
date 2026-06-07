import { useState } from 'react'
import { UploadCloud, X } from 'lucide-react'
import { Button } from '@components/ui/button'

export function ScopeFileUpload({ onFile }: { onFile: (text: string) => void }) {
  const [name, setName] = useState<string | null>(null)

  function handle(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]
    if (!f) return
    setName(f.name)
    const reader = new FileReader()
    reader.onload = () => onFile(String(reader.result || ''))
    reader.readAsText(f)
  }

  return (
    <div>
      <label className="block text-sm font-medium mb-1">Scope file (optional)</label>
      <div className="flex items-center gap-2">
        <label className="flex-1 cursor-pointer">
          <div className="border border-dashed border-line/50 rounded-md px-3 py-4
                          text-sm text-text-muted text-center hover:border-brand/50">
            <UploadCloud className="h-4 w-4 inline mr-1" />
            {name ? `Loaded: ${name}` : 'Click to upload .txt scope file'}
          </div>
          <input type="file" accept=".txt,.scope" className="hidden" onChange={handle} />
        </label>
        {name && (
          <Button variant="ghost" size="icon"
                  onClick={() => { setName(null); onFile('') }}
                  aria-label="Clear scope file">
            <X className="h-4 w-4" />
          </Button>
        )}
      </div>
    </div>
  )
}
