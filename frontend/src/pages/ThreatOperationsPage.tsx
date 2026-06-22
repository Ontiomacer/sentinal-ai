import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, ChevronDown, CircleDot, Network, Play, RefreshCw } from 'lucide-react'
import { useOutletContext, useParams } from 'react-router-dom'
import ThreatInvestigationWorkspace from '../components/threat-ops/ThreatInvestigationWorkspace'
import {
  CaseResponse,
  Evidence,
  getThreatOpsInvestigation,
  listCases,
  listEvidence,
  resumeThreatOpsInvestigation,
  startThreatOpsInvestigation,
  ThreatOpsInvestigation
} from '../services/caseApi'

interface CaseContextType {
  caseData: CaseResponse
  refreshCase: () => void
}

const parseAnalysisResult = (value: unknown): unknown => {
  if (typeof value !== 'string') return value || null
  try {
    return JSON.parse(value)
  } catch {
    return null
  }
}

const requestErrorMessage = (error: unknown, fallback: string) => {
  if (typeof error !== 'object' || error === null) return fallback
  const response = 'response' in error && typeof error.response === 'object' && error.response !== null
    ? error.response as { data?: unknown }
    : null
  const data = response?.data
  if (typeof data === 'object' && data !== null && 'detail' in data && typeof data.detail === 'string') {
    return data.detail
  }
  return 'message' in error && typeof error.message === 'string' ? error.message : fallback
}

const ThreatOperationsPage = () => {
  const params = useParams<{ scanId?: string; evidenceId?: string; caseId?: string }>()
  const caseContext = useOutletContext<CaseContextType | null>()
  const investigationId = params.evidenceId || params.scanId
  const caseId = params.caseId || caseContext?.caseData?.id
  const [evidenceItems, setEvidenceItems] = useState<Evidence[]>([])
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(investigationId || null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [investigation, setInvestigation] = useState<ThreatOpsInvestigation | null>(null)
  const [investigationLoading, setInvestigationLoading] = useState(false)

  const loadEvidence = useCallback(async (background = false) => {
    if (background) setRefreshing(true)
    else setLoading(true)
    setError(null)

    try {
      let apkEvidence: Evidence[] = []
      if (caseId) {
        const items = await listEvidence(caseId)
        apkEvidence = items.filter(item => item.evidence_type.toLowerCase() === 'apk')
      } else {
        const cases = await listCases()
        const results = await Promise.allSettled(cases.map(caseItem => listEvidence(caseItem.id)))
        apkEvidence = results.flatMap(result =>
          result.status === 'fulfilled'
            ? result.value.filter(item => item.evidence_type.toLowerCase() === 'apk')
            : []
        )
      }

      apkEvidence.sort((left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime())
      setEvidenceItems(apkEvidence)
      setSelectedEvidenceId(current => {
        if (current && apkEvidence.some(item => item.id === current)) return current
        if (investigationId && apkEvidence.some(item => item.id === investigationId)) return investigationId
        return apkEvidence[0]?.id || null
      })
    } catch (loadError) {
      console.error('Failed to load Threat Ops evidence:', loadError)
      setError('Threat Ops could not load case evidence from the analysis service.')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [caseId, investigationId])

  useEffect(() => {
    void loadEvidence()
  }, [loadEvidence])

  const selectedEvidence = evidenceItems.find(item => item.id === selectedEvidenceId) || null

  const loadInvestigation = useCallback(async (background = false) => {
    if (!selectedEvidence) {
      setInvestigation(null)
      return
    }
    if (!background) setInvestigationLoading(true)
    try {
      const persisted = await getThreatOpsInvestigation(selectedEvidence.case_id, selectedEvidence.id)
      setInvestigation(persisted)
      if (persisted?.status === 'failed' && persisted.error) {
        setError(`${persisted.error.exception_type}: ${persisted.error.exception_message}`)
      }
    } catch (loadError) {
      console.error('Failed to reload Threat Ops investigation:', loadError)
      setError(requestErrorMessage(loadError, 'Threat Ops could not reload the persisted investigation.'))
    } finally {
      if (!background) setInvestigationLoading(false)
    }
  }, [selectedEvidence])

  useEffect(() => {
    setInvestigation(null)
    setError(null)
    void loadInvestigation()
  }, [loadInvestigation])

  useEffect(() => {
    if (investigation?.status !== 'running') return
    const timer = window.setInterval(() => void loadInvestigation(true), 1000)
    return () => window.clearInterval(timer)
  }, [investigation?.status, loadInvestigation])

  const storedAnalysisResult = useMemo(
    () => parseAnalysisResult(selectedEvidence?.analysis_result),
    [selectedEvidence?.analysis_result]
  )

  const analysisResult = useMemo(() => {
    if (!investigation) return storedAnalysisResult
    return {
      ...investigation.result,
      investigation_stages: investigation.stages,
      investigation_status: investigation.status,
      investigation_error: investigation.error,
      investigation_started_at: investigation.started_at,
      investigation_finished_at: investigation.finished_at,
    }
  }, [investigation, storedAnalysisResult])

  const startInvestigation = async () => {
    if (!selectedEvidence) return
    setStarting(true)
    setError(null)
    try {
      const persisted = investigation?.status === 'failed'
        ? await resumeThreatOpsInvestigation(selectedEvidence.case_id, selectedEvidence.id)
        : await startThreatOpsInvestigation(selectedEvidence.case_id, selectedEvidence.id)
      setInvestigation(persisted)
    } catch (analysisError) {
      console.error('Failed to start Threat Ops investigation:', analysisError)
      setError(requestErrorMessage(analysisError, 'The Threat Ops investigation pipeline could not be started.'))
    } finally {
      setStarting(false)
    }
  }

  const caseName = caseContext?.caseData?.name || 'Cross-case intelligence'
  const canStart = Boolean(selectedEvidence && !investigation)
  const canResume = investigation?.status === 'failed'
  const canRun = canStart || canResume
  const isRunning = investigation?.status === 'running'
  const statusLabel = selectedEvidence
    ? isRunning
      ? 'Investigation running'
      : investigation?.status === 'completed'
        ? 'Investigation complete'
        : investigation?.status === 'failed'
          ? 'Investigation failed — resume available'
          : 'Ready for investigation'
    : 'Awaiting evidence'

  return (
    <div className="-mb-[120px] flex h-[calc(100vh-7.5rem)] min-h-[560px] flex-col overflow-hidden bg-[#050506] text-zinc-200">
      <header className="flex h-[58px] shrink-0 items-center border-b border-white/10 bg-[#08080a] px-3 sm:px-4">
        <div className="flex min-w-0 items-center gap-3">
          <div className="grid h-9 w-9 shrink-0 place-items-center border border-cyan-300/30 bg-cyan-300/[0.06]">
            <Network className="h-4.5 w-4.5 text-cyan-300" />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="truncate text-sm font-semibold text-white">Threat Ops</h1>
              <span className="hidden font-mono text-[9px] uppercase text-zinc-600 sm:inline">Investigation workspace</span>
            </div>
            <p className="truncate font-mono text-[9px] uppercase text-zinc-500">{caseName}</p>
          </div>
        </div>

        <div className="mx-3 flex min-w-0 flex-1 justify-center">
          {evidenceItems.length > 0 ? (
            <div className="relative w-full max-w-[420px]">
              <select
                value={selectedEvidenceId || ''}
                onChange={event => setSelectedEvidenceId(event.target.value)}
                aria-label="Select APK evidence"
                className="h-9 w-full appearance-none truncate border border-white/10 bg-black/50 px-3 pr-8 font-mono text-[10px] text-zinc-300 outline-none hover:border-white/20 focus:border-cyan-400/50"
              >
                {evidenceItems.map(item => (
                  <option key={item.id} value={item.id}>{item.original_filename}</option>
                ))}
              </select>
              <ChevronDown className="pointer-events-none absolute right-2.5 top-3 h-3.5 w-3.5 text-zinc-600" />
            </div>
          ) : (
            <span className="hidden font-mono text-[9px] uppercase text-zinc-700 sm:inline">No APK evidence available</span>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {canRun && (
            <button
              type="button"
              onClick={() => void startInvestigation()}
              disabled={starting}
              className="flex h-9 items-center gap-2 border border-cyan-300/40 bg-cyan-300/[0.08] px-3 font-mono text-[9px] uppercase text-cyan-200 hover:bg-cyan-300/[0.13] disabled:opacity-50"
            >
              {starting ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              <span className="hidden md:inline">{canResume ? 'Resume investigation' : 'Start investigation'}</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => void Promise.all([loadEvidence(true), loadInvestigation(true)])}
            disabled={refreshing}
            title="Refresh investigation data"
            className="grid h-9 w-9 place-items-center border border-white/10 text-zinc-500 hover:border-white/20 hover:text-white disabled:opacity-40"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
          <div className="hidden h-9 items-center gap-2 border border-white/10 bg-black/40 px-3 lg:flex">
            <CircleDot className={`h-3 w-3 ${isRunning ? 'animate-pulse text-cyan-300' : investigation?.status === 'completed' ? 'text-emerald-300' : investigation?.status === 'failed' ? 'text-rose-300' : 'text-zinc-600'}`} />
            <span className="font-mono text-[9px] uppercase text-zinc-500">{statusLabel}</span>
          </div>
        </div>
      </header>

      {error && (
        <div className="flex h-9 shrink-0 items-center gap-2 border-b border-rose-400/20 bg-rose-400/[0.07] px-4 font-mono text-[10px] text-rose-200">
          <AlertTriangle className="h-3.5 w-3.5" />
          {error}
        </div>
      )}

      <div className="min-h-0 flex-1">
        {loading || investigationLoading ? (
          <div className="grid h-full place-items-center forensic-grid-bg">
            <div className="text-center">
              <RefreshCw className="mx-auto mb-3 h-5 w-5 animate-spin text-cyan-300" />
              <p className="font-mono text-[10px] uppercase text-zinc-500">Synchronizing investigation evidence</p>
            </div>
          </div>
        ) : (
          <ThreatInvestigationWorkspace evidence={selectedEvidence} analysisResult={analysisResult} />
        )}
      </div>
    </div>
  )
}

export default ThreatOperationsPage
