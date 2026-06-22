import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import GlassPanel from '../components/ui/GlassPanel'
import ThreatBadge from '../components/ui/ThreatBadge'
import { listScans, ScanResponse } from '../services/api'

interface HistoryScan {
  scan_id: string
  filename: string
  created_at: string
  status: string
  risk_score?: number
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
}

const toHistoryScan = (scan: ScanResponse): HistoryScan => {
  const analysis = scan.analysis_result
  const risk = analysis?.risk_assessment || analysis?.threat_assessment || (analysis as any)?.intelligence?.risk_assessment
  return {
    scan_id: scan.scan_id,
    filename: scan.filename,
    created_at: scan.created_at,
    status: scan.status,
    risk_score: risk?.risk_score ?? risk?.overall_score,
    severity: risk?.severity ?? risk?.overall_severity,
  }
}

const historyRequestCache = new Map<string, Promise<ScanResponse[]>>()

const loadScanPage = (skip: number, limit: number) => {
  const key = `${skip}:${limit}`
  const cached = historyRequestCache.get(key)
  if (cached) return cached
  const request = listScans({ skip, limit }).finally(() => historyRequestCache.delete(key))
  historyRequestCache.set(key, request)
  return request
}

const ScanHistoryPage = () => {
  const [scans, setScans] = useState<HistoryScan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all')
  const [query, setQuery] = useState('')
  const [sortBy, setSortBy] = useState<'created_at' | 'filename' | 'risk_score' | 'status'>('created_at')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [page, setPage] = useState(0)
  const pageSize = 50

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        setLoading(true)
        setError(null)
        const rows = await loadScanPage(page * pageSize, pageSize)
        if (active) setScans(rows.map(toHistoryScan))
      } catch (err: any) {
        if (active) setError(err?.response?.data?.detail || err?.message || 'Failed to load scan history')
      } finally {
        if (active) setLoading(false)
      }
    }

    load()
    return () => {
      active = false
    }
  }, [page])

  const filteredScans = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    return scans
      .filter((scan) => {
        if (filter !== 'all' && scan.severity?.toLowerCase() !== filter) return false
        if (!normalizedQuery) return true
        return (
          scan.filename.toLowerCase().includes(normalizedQuery) ||
          scan.scan_id.toLowerCase().includes(normalizedQuery) ||
          scan.status.toLowerCase().includes(normalizedQuery)
        )
      })
      .sort((a, b) => {
        const direction = sortDir === 'asc' ? 1 : -1
        const left = a[sortBy] ?? ''
        const right = b[sortBy] ?? ''
        if (sortBy === 'risk_score') {
          return ((Number(left) || 0) - (Number(right) || 0)) * direction
        }
        return String(left).localeCompare(String(right)) * direction
      })
  }, [filter, query, scans, sortBy, sortDir])

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  return (
    <div className="container-padding fade-in">
      <section className="mb-24 relative max-w-4xl">
        <div className="flex items-center gap-2 mb-4">
          <ThreatBadge severity="MEDIUM" label="Threat Intelligence Archive" />
          <span className="text-on-surface-variant font-label-sm text-label-sm opacity-50">
            - {scans.length} TOTAL SCANS
          </span>
        </div>
        <h1 className="font-display-xl text-display-xl tracking-tighter text-on-surface leading-tight mb-6">
          SCAN HISTORY
        </h1>
        <p className="font-body-lg text-body-lg text-on-surface-variant max-w-2xl leading-relaxed">
          Access historical threat intelligence data and review past APK analyses. All scan results
          are preserved for forensic investigation and pattern recognition.
        </p>
      </section>

      <section className="mb-12">
        <GlassPanel className="p-4">
          <div className="flex items-center gap-4 flex-wrap">
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search scans"
              className="px-3 py-2 rounded bg-black/30 border border-white/10 text-sm text-on-surface outline-none focus:border-secondary/60"
            />
            <span className="font-label-sm text-label-sm text-on-surface-variant uppercase">
              Severity:
            </span>
            <div className="flex gap-2 flex-wrap">
              {(['all', 'critical', 'high', 'medium', 'low'] as const).map((value) => (
                <button
                  key={value}
                  onClick={() => {
                    setFilter(value)
                    setPage(0)
                  }}
                  className={`px-4 py-2 rounded font-label-sm text-label-sm uppercase transition-all ${
                    filter === value
                      ? 'bg-secondary text-on-secondary'
                      : 'glass-panel hover:border-secondary/40'
                  }`}
                >
                  {value}
                </button>
              ))}
            </div>
            <select
              value={sortBy}
              onChange={(event) => setSortBy(event.target.value as typeof sortBy)}
              className="px-3 py-2 rounded bg-black/30 border border-white/10 text-sm text-on-surface outline-none"
            >
              <option value="created_at">Date</option>
              <option value="filename">Filename</option>
              <option value="risk_score">Risk Score</option>
              <option value="status">Status</option>
            </select>
            <button
              onClick={() => setSortDir((value) => value === 'asc' ? 'desc' : 'asc')}
              className="px-4 py-2 rounded glass-panel hover:border-secondary/40 font-label-sm text-label-sm uppercase"
            >
              {sortDir === 'asc' ? 'Asc' : 'Desc'}
            </button>
          </div>
        </GlassPanel>
      </section>

      <section className="mb-section-gap">
        {loading ? (
          <div className="text-center py-24">
            <span className="material-symbols-outlined text-6xl text-secondary animate-spin mb-4 block">
              progress_activity
            </span>
            <p className="font-title-md text-title-md text-on-surface">Loading scan history...</p>
          </div>
        ) : error ? (
          <GlassPanel className="p-12 text-center">
            <span className="material-symbols-outlined text-6xl text-error mb-4 block">
              error
            </span>
            <p className="font-title-md text-title-md text-on-surface mb-2">Scan history unavailable</p>
            <p className="text-body-md text-on-surface-variant mb-6">{error}</p>
          </GlassPanel>
        ) : filteredScans.length === 0 ? (
          <GlassPanel className="p-12 text-center">
            <span className="material-symbols-outlined text-6xl text-on-surface-variant mb-4 block">
              folder_open
            </span>
            <p className="font-title-md text-title-md text-on-surface mb-2">No scans found</p>
            <p className="text-body-md text-on-surface-variant mb-6">
              {filter === 'all' ? 'Upload an APK to get started' : `No ${filter} severity scans found`}
            </p>
            <Link to="/" className="btn-secondary px-6 py-3 inline-flex items-center gap-2">
              <span className="material-symbols-outlined">upload</span>
              Upload APK
            </Link>
          </GlassPanel>
        ) : (
          <div className="space-y-4">
            {filteredScans.map((scan) => (
              <Link key={scan.scan_id} to={`/scan/${scan.scan_id}`}>
                <GlassPanel className="p-6 hover:border-secondary/40 transition-all duration-300 cursor-pointer">
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-4 mb-2 flex-wrap">
                        <h3 className="font-title-md text-title-md text-on-surface truncate">
                          {scan.filename}
                        </h3>
                        {scan.severity && (
                          <ThreatBadge severity={scan.severity} label={scan.severity} />
                        )}
                      </div>
                      <div className="flex items-center gap-6 text-on-surface-variant font-label-sm text-label-sm flex-wrap">
                        <span>SCAN ID: {scan.scan_id.substring(0, 8).toUpperCase()}</span>
                        <span>{formatDate(scan.created_at)}</span>
                        <span className="flex items-center gap-1">
                          <span className={`w-2 h-2 rounded-full ${
                            scan.status === 'completed' ? 'bg-tertiary' :
                            scan.status === 'analyzing' || scan.status === 'pending' ? 'bg-secondary animate-pulse' :
                            'bg-error'
                          }`}></span>
                          {scan.status.toUpperCase()}
                        </span>
                      </div>
                    </div>
                    {scan.risk_score !== undefined && (
                      <div className="text-right">
                        <span className="text-on-surface-variant font-label-sm text-label-sm block mb-1">
                          RISK SCORE
                        </span>
                        <span className={`font-display-xl text-title-md ${
                          scan.severity === 'CRITICAL' ? 'text-error' :
                          scan.severity === 'HIGH' ? 'text-secondary' :
                          scan.severity === 'MEDIUM' ? 'text-primary' : 'text-tertiary'
                        }`}>
                          {scan.risk_score}/100
                        </span>
                      </div>
                    )}
                    <span className="material-symbols-outlined text-on-surface-variant">
                      arrow_forward
                    </span>
                  </div>
                </GlassPanel>
              </Link>
            ))}
          </div>
        )}
      </section>

      <section className="mb-12">
        <div className="flex items-center justify-between text-sm text-on-surface-variant">
          <button
            onClick={() => setPage((value) => Math.max(0, value - 1))}
            disabled={page === 0 || loading}
            className="px-4 py-2 rounded glass-panel disabled:opacity-40"
          >
            Previous
          </button>
          <span>Page {page + 1}</span>
          <button
            onClick={() => setPage((value) => value + 1)}
            disabled={loading || scans.length < pageSize}
            className="px-4 py-2 rounded glass-panel disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </section>

      <section>
        <h2 className="font-title-md text-title-md text-on-surface mb-12 flex items-center gap-4">
          THREAT STATISTICS
          <div className="h-px bg-white/10 flex-grow"></div>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-gutter">
          <GlassPanel className="p-6">
            <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-2">
              Total Scans
            </span>
            <span className="font-display-xl text-title-md text-on-surface">{scans.length}</span>
          </GlassPanel>

          <GlassPanel className="p-6">
            <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-2">
              Critical Threats
            </span>
            <span className="font-display-xl text-title-md text-error">
              {scans.filter((scan) => scan.severity === 'CRITICAL').length}
            </span>
          </GlassPanel>

          <GlassPanel className="p-6">
            <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-2">
              High Risk
            </span>
            <span className="font-display-xl text-title-md text-secondary">
              {scans.filter((scan) => scan.severity === 'HIGH').length}
            </span>
          </GlassPanel>

          <GlassPanel className="p-6">
            <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-2">
              Low Risk
            </span>
            <span className="font-display-xl text-title-md text-tertiary">
              {scans.filter((scan) => scan.severity === 'LOW').length}
            </span>
          </GlassPanel>
        </div>
      </section>
    </div>
  )
}

export default ScanHistoryPage
