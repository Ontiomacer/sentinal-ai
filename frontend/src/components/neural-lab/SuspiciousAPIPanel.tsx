import React, { useState, useEffect } from 'react'
import GlassPanel from '../ui/GlassPanel'
import { neuralApi } from '../../services/neuralApi'

interface SuspiciousFunction {
  name: string
  class_name: string
  signature: string
  threat_indicators: string[]
  decompiled_code?: string
  risk_score: number
  call_count: number
  called_by?: string[]
  calls_to?: string[]
}

interface SuspiciousAPIPanelProps {
  scanId: string
  functions: SuspiciousFunction[]
  activeInvestigationId: string | undefined
  onAddBookmark: (targetType: string, targetId: string, label: string, notes: string, severity: string) => void
}

export const SuspiciousAPIPanel: React.FC<SuspiciousAPIPanelProps> = ({
  scanId,
  functions,
  activeInvestigationId,
  onAddBookmark,
}) => {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedFunc, setSelectedFunc] = useState<SuspiciousFunction | null>(null)
  
  // Explanation state
  const [explanation, setExplanation] = useState('')
  const [interpretation, setInterpretation] = useState<any | null>(null)
  const [explaining, setExplaining] = useState(false)

  // Bookmark inputs
  const [bookmarkNotes, setBookmarkNotes] = useState('')
  const [bookmarkSeverity, setBookmarkSeverity] = useState('medium')
  const [showBookmarkForm, setShowBookmarkForm] = useState(false)

  useEffect(() => {
    const handleInternalSelect = (e: any) => {
      const { signature } = e.detail
      const func = functions.find(f => f.signature === signature)
      if (func) {
        handleSelect(func)
      }
    }

    window.addEventListener('sentinel:internal-select-function', handleInternalSelect)
    return () => window.removeEventListener('sentinel:internal-select-function', handleInternalSelect)
  }, [functions])

  const filtered = functions.filter((f) => {
    const s = searchTerm.toLowerCase()
    return f.name.toLowerCase().includes(s) || f.class_name.toLowerCase().includes(s)
  })

  const handleSelect = (func: SuspiciousFunction) => {
    setSelectedFunc(func)
    setExplanation('')
    setInterpretation(null)
    setShowBookmarkForm(false)
    setBookmarkNotes('')
  }

  const handleExplain = async () => {
    if (!selectedFunc) return
    if (!selectedFunc.decompiled_code) {
      setExplanation('Code interpretation unavailable because this function has no cached decompiled source.')
      setInterpretation({
        status: 'unavailable',
        purpose: 'Source unavailable.',
        behavior: 'No behavior was inferred because decompiled source was not available.',
        security_impact: 'Unavailable.',
        fraud_impact: 'Unavailable.',
        confidence: 0,
        evidence: [],
      })
      return
    }
    setExplaining(true)
    setExplanation('')
    setInterpretation(null)
    try {
      const res = await neuralApi.explainCode(scanId, selectedFunc.decompiled_code, selectedFunc.name, selectedFunc.class_name)
      setExplanation(res.explanation)
      setInterpretation(res.interpretation || null)
    } catch (e: any) {
      setExplanation(`Forensic explanation failed: ${e.message || 'Connection failure'}`)
    } finally {
      setExplaining(false)
    }
  }

  const handleSaveBookmark = () => {
    if (!selectedFunc) return
    onAddBookmark(
      'function',
      selectedFunc.signature,
      selectedFunc.name,
      bookmarkNotes,
      bookmarkSeverity
    )
    setShowBookmarkForm(false)
    setBookmarkNotes('')
  }

  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-error border-error/20 bg-error/5'
    if (score >= 40) return 'text-warning border-warning/20 bg-warning/5'
    return 'text-success border-success/20 bg-success/5'
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs select-none h-[500px]">
      
      {/* Search & List */}
      <GlassPanel className="p-4 col-span-1 border-border bg-surface-variant/10 flex flex-col h-full">
        <div className="relative mb-3">
          <input
            type="text"
            placeholder="Search API signatures..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-surface border border-border rounded-md py-1.5 pl-8 pr-3 text-xs focus:outline-none focus:border-primary text-on-surface"
          />
          <span className="material-symbols-outlined text-sm absolute left-2.5 top-2.5 opacity-55">
            search
          </span>
        </div>

              <div className="flex-1 overflow-y-auto pr-1 space-y-1.5">
                {filtered.length === 0 ? (
                  <div className="text-center py-12 opacity-50">No API matches.</div>
                ) : (
                  filtered.map((f, idx) => (
                    <button
                      key={`${f.signature}-${idx}`}
                      onClick={() => handleSelect(f)}
                      className={`w-full text-left p-2.5 border rounded-md transition-all flex items-center justify-between gap-2 ${
                        selectedFunc?.signature === f.signature
                          ? 'border-primary bg-primary/5'
                          : 'border-border bg-surface/30 hover:border-border-hover'
                      }`}
                    >
                <div className="truncate">
                  <span className="font-semibold text-on-surface block truncate">{f.name}</span>
                  <span className="text-[10px] text-on-surface-variant opacity-60 block truncate">{f.class_name}</span>
                </div>
                <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold border ${getRiskColor(f.risk_score)}`}>
                  {f.risk_score}
                </span>
              </button>
            ))
          )}
        </div>
      </GlassPanel>

      {/* Editor & AI Code details */}
      <GlassPanel className="p-6 col-span-1 lg:col-span-2 border-border bg-surface-variant/10 flex flex-col h-full overflow-hidden">
        {selectedFunc ? (
          <div className="flex flex-col h-full">
            <div className="flex items-center justify-between border-b border-border pb-3 mb-3">
              <div>
                <h4 className="font-bold text-on-surface text-sm">{selectedFunc.name}</h4>
                <p className="text-[10px] text-on-surface-variant opacity-60">{selectedFunc.signature}</p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleExplain}
                  disabled={explaining}
                  className="px-3 py-1.5 rounded-md bg-secondary hover:bg-secondary/90 text-on-secondary font-bold text-[10px] flex items-center gap-1"
                >
                  <span className="material-symbols-outlined text-[12px]">psychology</span>
                  {explaining ? 'EXPLAINING...' : 'AI EXPLAIN'}
                </button>
                {activeInvestigationId && (
                  <button
                    onClick={() => setShowBookmarkForm(!showBookmarkForm)}
                    className="px-3 py-1.5 rounded-md border border-border hover:bg-surface-variant text-on-surface-variant hover:text-on-surface font-bold text-[10px] flex items-center gap-1"
                  >
                    <span className="material-symbols-outlined text-[12px]">bookmark</span>
                    BOOKMARK
                  </button>
                )}
              </div>
            </div>

            {/* Bookmark form drawer */}
            {showBookmarkForm && (
              <div className="p-3 border border-border bg-surface/60 rounded-md mb-3 space-y-2">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-primary">Bookmark Findings Note</span>
                  <select
                    value={bookmarkSeverity}
                    onChange={(e) => setBookmarkSeverity(e.target.value)}
                    className="bg-surface border border-border rounded px-1.5 py-0.5"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                <textarea
                  placeholder="Annotate code vulnerabilities or IOC findings..."
                  value={bookmarkNotes}
                  onChange={(e) => setBookmarkNotes(e.target.value)}
                  className="w-full h-12 bg-surface border border-border rounded p-1.5 focus:outline-none"
                />
                <div className="flex justify-end gap-2">
                  <button
                    onClick={() => setShowBookmarkForm(false)}
                    className="px-2 py-1 border border-border rounded"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSaveBookmark}
                    className="px-2 py-1 bg-primary text-on-primary rounded"
                  >
                    Save
                  </button>
                </div>
              </div>
            )}

            {/* Tabbed details */}
            <div className="flex-1 overflow-y-auto space-y-4 pr-1">
              <div>
                <h5 className="font-semibold text-primary mb-1">Threat Indicators</h5>
                <div className="flex flex-wrap gap-1">
                  {selectedFunc.threat_indicators.map((ind) => (
                    <span key={ind} className="bg-surface-variant/40 px-2 py-0.5 rounded text-[10px] border border-border">
                      {ind}
                    </span>
                  ))}
                </div>
              </div>

              <div>
                <h5 className="font-semibold text-primary mb-1">Source Code / Decompilation</h5>
                <pre className="p-3 rounded bg-surface border border-border overflow-x-auto text-[10px] leading-relaxed text-on-surface font-mono max-h-[160px]">
                  <code>
                    {selectedFunc.decompiled_code || '// Decompiled source unavailable for this function. Run JADX/Ghidra analysis and reopen the artifact.'}
                  </code>
                </pre>
              </div>

              {interpretation && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {[
                    ['Purpose', interpretation.purpose],
                    ['Behavior', interpretation.behavior],
                    ['Security Impact', interpretation.security_impact],
                    ['Fraud Impact', interpretation.fraud_impact],
                  ].map(([label, value]) => (
                    <div key={label} className="p-3 rounded border border-border bg-surface/50">
                      <h5 className="font-semibold text-primary mb-1">{label}</h5>
                      <p className="text-[10px] text-on-surface-variant leading-relaxed">{value || 'Unavailable.'}</p>
                    </div>
                  ))}
                  <div className="p-3 rounded border border-border bg-surface/50 md:col-span-2">
                    <h5 className="font-semibold text-primary mb-1">Confidence</h5>
                    <p className="text-[10px] text-on-surface-variant">{interpretation.confidence ?? 0}%</p>
                    {interpretation.evidence?.length > 0 && (
                      <div className="mt-2 space-y-1">
                        {interpretation.evidence.slice(0, 6).map((item: string, idx: number) => (
                          <div key={idx} className="text-[9px] text-on-surface-variant/80 truncate select-text">
                            &gt; {item}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* AI Explanation container */}
              {(explanation || explaining) && (
                <div className="p-4 rounded-lg border border-primary/20 bg-primary/5">
                  <h5 className="font-semibold text-primary flex items-center gap-1.5 mb-1.5">
                    <span className="material-symbols-outlined text-sm animate-pulse-slow">psychology</span>
                    Forensic AI Insight
                  </h5>
                  {explaining ? (
                    <div className="flex items-center gap-2 text-on-surface-variant opacity-75">
                      <span className="material-symbols-outlined animate-spin text-sm">sync</span>
                      Deconstructing bytecode heuristics...
                    </div>
                  ) : (
                    <p className="text-on-surface-variant leading-relaxed font-mono text-[11px] whitespace-pre-wrap">{explanation}</p>
                  )}
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-center opacity-50">
            <span className="material-symbols-outlined text-4xl mb-2">code</span>
            Select an API signature on the left pane to view reconstructed source files.
          </div>
        )}
      </GlassPanel>
    </div>
  )
}
export default SuspiciousAPIPanel
