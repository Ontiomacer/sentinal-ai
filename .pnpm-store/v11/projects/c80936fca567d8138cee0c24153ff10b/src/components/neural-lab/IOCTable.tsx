import React, { useState } from 'react'
import GlassPanel from '../ui/GlassPanel'

interface MalwareIndicator {
  type: string
  value: string
  context: string
  severity: string
  description: string
  locations?: string[]
}

interface IOCTableProps {
  indicators: MalwareIndicator[]
}

export const IOCTable: React.FC<IOCTableProps> = ({ indicators }) => {
  const [searchTerm, setSearchTerm] = useState('')
  const [copiedValue, setCopiedValue] = useState<string | null>(null)

  const filtered = indicators.filter((i) => {
    const term = searchTerm.toLowerCase()
    return (
      i.value.toLowerCase().includes(term) ||
      i.type.toLowerCase().includes(term) ||
      i.severity.toLowerCase().includes(term)
    )
  })

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val)
    setCopiedValue(val)
    setTimeout(() => setCopiedValue(null), 2000)
  }

  const exportCSV = () => {
    const header = 'Type,Value,Severity,Context\n'
    const rows = filtered
      .map((i) => {
        const val = i.value.replace(/"/g, '""')
        const ctx = i.context.replace(/"/g, '""')
        return `"${i.type}","${val}","${i.severity}","${ctx}"`
      })
      .join('\n')
    
    const blob = new Blob([header + rows], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.setAttribute('href', url)
    link.setAttribute('download', `specter_iocs_${new Date().toISOString().split('T')[0]}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  const getSeverityStyle = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'text-error border-error/20 bg-error/5'
      case 'medium':
        return 'text-warning border-warning/20 bg-warning/5'
      default:
        return 'text-success border-success/20 bg-success/5'
    }
  }

  return (
    <div className="space-y-4 font-mono text-xs select-none">
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 bg-surface-variant/10 p-4 border border-border rounded-xl">
        <div className="relative flex-1 max-w-sm">
          <input
            type="text"
            placeholder="Filter IOC attributes..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-surface border border-border rounded-md py-1.5 pl-8 pr-3 text-xs focus:outline-none focus:border-primary text-on-surface"
          />
          <span className="material-symbols-outlined text-sm absolute left-2.5 top-2.5 opacity-55">
            search
          </span>
        </div>
        <button
          onClick={exportCSV}
          className="btn-secondary px-4 py-1.5 text-[10px] border border-border bg-surface-variant/30 hover:bg-surface-variant flex items-center gap-1.5"
        >
          <span className="material-symbols-outlined text-sm">download</span>
          EXPORT CSV
        </button>
      </div>

      <GlassPanel className="border-border bg-surface-variant/5 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-border bg-surface-variant/30 text-[10px] font-bold uppercase tracking-wider text-on-surface-variant">
                <th className="p-3">Type</th>
                <th className="p-3">Value</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Forensic Context</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={4} className="p-8 text-center text-on-surface-variant opacity-60">
                    No Indicators of Compromise extracted.
                  </td>
                </tr>
              ) : (
                filtered.map((i, idx) => (
                  <tr key={idx} className="hover:bg-surface-variant/15 transition-colors">
                    <td className="p-3 font-semibold text-primary uppercase text-[10px]">{i.type}</td>
                    <td className="p-3 font-mono max-w-[250px] truncate select-text">
                      <div className="flex items-center gap-2">
                        <span className="truncate">{i.value}</span>
                        <button
                          onClick={() => handleCopy(i.value)}
                          className="text-on-surface-variant hover:text-on-surface p-0.5 rounded transition-colors"
                          title="Copy IOC Value"
                        >
                          <span className="material-symbols-outlined text-[12px] block">
                            {copiedValue === i.value ? 'done' : 'content_copy'}
                          </span>
                        </button>
                      </div>
                    </td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded border text-[9px] font-bold ${getSeverityStyle(i.severity)}`}>
                        {i.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="p-3 text-[10px] text-on-surface-variant truncate max-w-[300px]">
                      {i.context}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </GlassPanel>
    </div>
  )
}
export default IOCTable
