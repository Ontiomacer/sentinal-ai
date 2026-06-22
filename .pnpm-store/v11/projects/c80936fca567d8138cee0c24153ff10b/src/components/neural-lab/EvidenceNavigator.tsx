import { ScanResponse } from '../../services/api'

interface EvidenceNavigatorProps {
  scan: ScanResponse
  suspiciousFunctions: any[]
  malwareIndicators: any[]
  behavioralPatterns: any[]
  permissions: string[]
  aiHealthy: boolean
}

const EvidenceNavigator = ({
  scan,
  suspiciousFunctions,
  malwareIndicators,
  behavioralPatterns,
  permissions,
  aiHealthy,
}: EvidenceNavigatorProps) => {
  const analysis = scan.analysis_result
  const navRows = [
    ['APP', analysis?.app_name || scan.filename],
    ['PACKAGE', analysis?.package_name || 'unknown.package'],
    ['SHA256', scan.sha256],
    ['STATUS', scan.status],
  ]

  const counters = [
    ['FUNCTIONS', suspiciousFunctions.length],
    ['IOCS', malwareIndicators.length],
    ['BEHAVIORS', behavioralPatterns.length],
    ['PERMS', permissions.length],
  ]

  return (
    <div className="space-y-4">
      <div className="workstation-panel">
        <div className="workstation-panel-header">
          <span className="material-symbols-outlined text-[18px]">account_tree</span>
          <span>EVIDENCE NAVIGATOR</span>
        </div>
        <div className="p-4 space-y-3">
          {navRows.map(([label, value]) => (
            <div key={label}>
              <div className="font-mono text-[10px] text-on-surface-variant tracking-[0.16em] mb-1">
                {label}
              </div>
              <div className="font-mono text-[12px] text-on-surface break-all">
                {value}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        {counters.map(([label, value]) => (
          <div key={label} className="border border-white/10 bg-black/35 p-3">
            <div className="font-mono text-[10px] text-on-surface-variant tracking-[0.14em]">
              {label}
            </div>
            <div className="font-mono text-xl text-on-surface">{value}</div>
          </div>
        ))}
      </div>

      <div className="workstation-panel">
        <div className="workstation-panel-header">
          <span className="material-symbols-outlined text-[18px]">psychology</span>
          <span>AI LINK</span>
        </div>
        <div className="p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="font-mono text-[11px] text-on-surface-variant">OLLAMA</span>
            <span className={`w-2 h-2 rounded-full ${aiHealthy ? 'bg-white' : 'bg-white/25'}`} />
          </div>
          <p className="text-[12px] leading-5 text-on-surface-variant">
            {aiHealthy
              ? 'Local cognition model is ready for explanations, chat, and summaries.'
              : 'Local cognition model is offline. Rule-based panels remain available.'}
          </p>
        </div>
      </div>
    </div>
  )
}

export default EvidenceNavigator
