import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import GlassPanel from './ui/GlassPanel'
import { AISuggestionsResponse, aiApi } from '../services/aiApi'

interface AISuggestionsPanelProps {
  caseId?: string
  evidenceId?: string
  scanId?: string
  context?: Record<string, any>
  className?: string
}

const severityClass = (severity: string) => {
  const normalized = severity.toLowerCase()
  if (normalized === 'critical' || normalized === 'high') return 'border-white/60 bg-white/10'
  if (normalized === 'medium') return 'border-white/30 bg-white/[0.07]'
  return 'border-white/15 bg-white/5'
}

const AISuggestionsPanel = ({
  caseId,
  evidenceId,
  scanId,
  context = {},
  className = '',
}: AISuggestionsPanelProps) => {
  const [data, setData] = useState<AISuggestionsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    const load = async () => {
      try {
        setLoading(true)
        setError(null)
        const response = await aiApi.suggestions({
          case_id: caseId,
          evidence_id: evidenceId,
          scan_id: scanId,
          context,
          use_ai: false,
        })
        if (!cancelled) setData(response)
      } catch (err: any) {
        if (!cancelled) setError(err?.message || 'AI suggestions unavailable')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    load()
    const timer = window.setInterval(load, 45000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [caseId, evidenceId, scanId, JSON.stringify(context)])

  return (
    <GlassPanel className={`mono-panel p-0 overflow-hidden ${className}`}>
      <div className="workstation-panel-header justify-between">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-[18px] text-on-surface">psychology</span>
          <span>AI INVESTIGATOR CUE STACK</span>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px] text-on-surface-variant">
          <span className={`w-1.5 h-1.5 rounded-full ${data?.health?.healthy ? 'bg-white' : 'bg-white/30'}`} />
          {data?.ai_powered ? 'OLLAMA ASSISTED' : 'RULE GROUNDED'}
        </div>
      </div>

      <div className="p-5">
        {loading && (
          <div className="flex items-center gap-3 text-on-surface-variant font-mono text-[12px]">
            <span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span>
            READING CASE STATE
          </div>
        )}

        {error && !loading && (
          <div className="border border-white/15 bg-black/40 p-4 font-mono text-[12px] text-on-surface-variant">
            {error}
          </div>
        )}

        {data && !loading && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
              {[
                ['EVIDENCE', data.evidence_count],
                ['TIMELINE', data.timeline_count],
                ['ENTITIES', data.entity_count],
                ['NOTES', data.note_count],
              ].map(([label, value]) => (
                <div key={label} className="border border-white/10 bg-black/30 px-3 py-2">
                  <div className="font-mono text-[10px] text-on-surface-variant tracking-[0.16em]">{label}</div>
                  <div className="font-mono text-xl text-on-surface">{value}</div>
                </div>
              ))}
            </div>

            <div className="space-y-3">
              {data.suggestions.map((suggestion) => (
                <div
                  key={suggestion.id}
                  className={`border-l-2 p-4 ${severityClass(suggestion.severity)}`}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-[10px] text-on-surface-variant tracking-[0.18em]">
                          {suggestion.source.toUpperCase()} / {suggestion.severity.toUpperCase()}
                        </span>
                      </div>
                      <h3 className="font-title-md text-[17px] leading-6 text-on-surface">
                        {suggestion.title}
                      </h3>
                      <p className="text-[13px] leading-6 text-on-surface-variant mt-2">
                        {suggestion.detail}
                      </p>
                    </div>
                    {suggestion.route && suggestion.action && (
                      <Link
                        to={suggestion.route}
                        className="shrink-0 px-3 py-2 border border-white/20 bg-white text-black font-mono text-[10px] tracking-[0.14em] hover:bg-white/80 transition-colors"
                      >
                        {suggestion.action.toUpperCase()}
                      </Link>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </GlassPanel>
  )
}

export default AISuggestionsPanel
