import { useState, useEffect } from 'react'
import { useParams, Link, Outlet, useLocation } from 'react-router-dom'
import GlassPanel from '../components/ui/GlassPanel'
import ThreatBadge from '../components/ui/ThreatBadge'
import { getCase, CaseResponse } from '../services/caseApi'

const caseRequestCache = new Map<string, Promise<CaseResponse>>()

const loadCase = (caseId: string) => {
  const cached = caseRequestCache.get(caseId)
  if (cached) return cached
  const request = getCase(caseId).finally(() => caseRequestCache.delete(caseId))
  caseRequestCache.set(caseId, request)
  return request
}

const CaseWorkspacePage = () => {
  const { caseId } = useParams<{ caseId: string }>()
  const location = useLocation()
  const [caseData, setCaseData] = useState<CaseResponse | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!caseId) return

    let active = true
    const fetchCase = async () => {
      setLoading(true)
      try {
        const data = await loadCase(caseId)
        if (active) setCaseData(data)
      } catch (error) {
        console.error('Failed to fetch case:', error)
        if (active) setCaseData(null)
      } finally {
        if (active) setLoading(false)
      }
    }

    fetchCase()

    return () => {
      active = false
    }
  }, [caseId])

  const refreshCase = async () => {
    if (!caseId) return
    try {
      setLoading(true)
      const data = await getCase(caseId)
      setCaseData(data)
    } catch (error) {
      console.error('Failed to fetch case:', error)
    } finally {
      setLoading(false)
    }
  }

  const isActiveTab = (path: string) => {
    if (path === '' && location.pathname === `/cases/${caseId}`) {
      return true
    }
    return location.pathname.includes(path)
  }

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  if (loading) {
    return (
      <div className="container-padding flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <div className="relative mb-6">
            <span className="material-symbols-outlined text-6xl text-secondary">
              folder_open
            </span>
            <div className="absolute inset-0 border-2 border-secondary/30 rounded-full animate-ping"></div>
          </div>
          <p className="font-title-md text-title-md text-on-surface mb-2">
            Loading Investigation Workspace
          </p>
          <p className="font-label-sm text-label-sm text-on-surface-variant font-mono">
            [ Accessing Case Vault ]
          </p>
        </div>
      </div>
    )
  }

  if (!caseData) {
    return (
      <div className="container-padding">
        <GlassPanel className="p-12 text-center">
          <span className="material-symbols-outlined text-6xl text-error mb-4 block">error</span>
          <h2 className="font-title-md text-title-md text-on-surface mb-2">Case Not Found</h2>
          <Link to="/cases" className="btn-secondary px-6 py-3 inline-flex items-center gap-2 mt-4">
            <span className="material-symbols-outlined">arrow_back</span>
            Return to Cases
          </Link>
        </GlassPanel>
      </div>
    )
  }

  return (
    <div className="container-padding fade-in">
      {/* Case Header */}
      <section className="mb-8 relative max-w-7xl">
        <div className="flex items-start justify-between mb-6">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-4">
              <Link
                to="/cases"
                className="text-on-surface-variant hover:text-secondary transition-colors"
              >
                <span className="material-symbols-outlined">arrow_back</span>
              </Link>
              <span className="font-mono text-label-sm text-on-surface-variant">
                {caseData.id}
              </span>
              <ThreatBadge
                severity={caseData.severity.toUpperCase() as any}
                label={caseData.severity}
              />
              <span className={`px-3 py-1 rounded font-label-sm text-label-sm ${
                caseData.status === 'active'
                  ? 'bg-secondary/10 text-secondary'
                  : 'bg-on-surface-variant/10 text-on-surface-variant'
              }`}>
                {caseData.status.toUpperCase()}
              </span>
            </div>
            <h1 className="font-display-lg text-display-lg tracking-tighter text-on-surface leading-tight mb-3">
              {caseData.name}
            </h1>
            {caseData.description && (
              <p className="font-body-lg text-body-lg text-on-surface-variant max-w-4xl leading-relaxed">
                {caseData.description}
              </p>
            )}
          </div>

          <div className="flex gap-2">
            <button className="btn-secondary px-4 py-2 inline-flex items-center gap-2">
              <span className="material-symbols-outlined">download</span>
              EXPORT
            </button>
            <button className="btn-secondary px-4 py-2 inline-flex items-center gap-2">
              <span className="material-symbols-outlined">settings</span>
            </button>
          </div>
        </div>

        {/* Case Metadata */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div>
            <span className="font-label-sm text-label-sm text-on-surface-variant block mb-1">
              INVESTIGATOR
            </span>
            <span className="text-body-md text-on-surface">{caseData.investigator}</span>
          </div>
          {caseData.client_name && (
            <div>
              <span className="font-label-sm text-label-sm text-on-surface-variant block mb-1">
                CLIENT
              </span>
              <span className="text-body-md text-on-surface">{caseData.client_name}</span>
            </div>
          )}
          <div>
            <span className="font-label-sm text-label-sm text-on-surface-variant block mb-1">
              CREATED
            </span>
            <span className="text-body-md text-on-surface">{formatDate(caseData.created_at)}</span>
          </div>
          <div>
            <span className="font-label-sm text-label-sm text-on-surface-variant block mb-1">
              LAST UPDATED
            </span>
            <span className="text-body-md text-on-surface">
              {caseData.updated_at ? formatDate(caseData.updated_at) : 'Never'}
            </span>
          </div>
        </div>

        {/* Tags */}
        {caseData.tags && caseData.tags.length > 0 && (
          <div className="flex gap-2 flex-wrap">
            {caseData.tags.map((tag, idx) => (
              <span
                key={idx}
                className="px-3 py-1 bg-primary/10 text-primary font-label-sm text-label-sm rounded"
              >
                {tag}
              </span>
            ))}
          </div>
        )}
      </section>

      {/* Navigation Tabs */}
      <section className="mb-8 max-w-7xl">
        <GlassPanel className="p-2">
          <div className="flex gap-2 overflow-x-auto">
            <Link
              to={`/cases/${caseId}`}
              className={`px-6 py-3 rounded font-label-sm text-label-sm transition-all whitespace-nowrap ${
                isActiveTab('')
                  ? 'bg-secondary text-on-secondary'
                  : 'hover:bg-surface-container-high'
              }`}
            >
              <span className="material-symbols-outlined text-sm mr-2 align-middle">dashboard</span>
              OVERVIEW
            </Link>
            <Link
              to={`/cases/${caseId}/evidence`}
              className={`px-6 py-3 rounded font-label-sm text-label-sm transition-all whitespace-nowrap ${
                isActiveTab('evidence')
                  ? 'bg-secondary text-on-secondary'
                  : 'hover:bg-surface-container-high'
              }`}
            >
              <span className="material-symbols-outlined text-sm mr-2 align-middle">inventory_2</span>
              EVIDENCE ({caseData.evidence_count})
            </Link>
            <Link
              to={`/cases/${caseId}/files`}
              className={`px-6 py-3 rounded font-label-sm text-label-sm transition-all whitespace-nowrap ${
                isActiveTab('files')
                  ? 'bg-secondary text-on-secondary'
                  : 'hover:bg-surface-container-high'
              }`}
            >
              <span className="material-symbols-outlined text-sm mr-2 align-middle">folder_managed</span>
              FILES
            </Link>
            <Link
              to={`/cases/${caseId}/timeline`}
              className={`px-6 py-3 rounded font-label-sm text-label-sm transition-all whitespace-nowrap ${
                isActiveTab('timeline')
                  ? 'bg-secondary text-on-secondary'
                  : 'hover:bg-surface-container-high'
              }`}
            >
              <span className="material-symbols-outlined text-sm mr-2 align-middle">timeline</span>
              TIMELINE ({caseData.timeline_count})
            </Link>
            <Link
              to={`/cases/${caseId}/entities`}
              className={`px-6 py-3 rounded font-label-sm text-label-sm transition-all whitespace-nowrap ${
                isActiveTab('entities')
                  ? 'bg-secondary text-on-secondary'
                  : 'hover:bg-surface-container-high'
              }`}
            >
              <span className="material-symbols-outlined text-sm mr-2 align-middle">hub</span>
              ENTITIES ({caseData.entity_count})
            </Link>
            <Link
              to={`/cases/${caseId}/notes`}
              className={`px-6 py-3 rounded font-label-sm text-label-sm transition-all whitespace-nowrap ${
                isActiveTab('notes')
                  ? 'bg-secondary text-on-secondary'
                  : 'hover:bg-surface-container-high'
              }`}
            >
              <span className="material-symbols-outlined text-sm mr-2 align-middle">description</span>
              NOTES ({caseData.note_count})
            </Link>
            <Link
              to={`/cases/${caseId}/code-analysis`}
              className={`px-6 py-3 rounded font-label-sm text-label-sm transition-all whitespace-nowrap ${
                isActiveTab('code-analysis')
                  ? 'bg-secondary text-on-secondary'
                  : 'hover:bg-surface-container-high'
              }`}
            >
              <span className="material-symbols-outlined text-sm mr-2 align-middle">code</span>
              CODE ANALYSIS
            </Link>
            <Link
              to={`/cases/${caseId}/neural-lab`}
              className={`px-6 py-3 rounded font-label-sm text-label-sm transition-all whitespace-nowrap ${
                isActiveTab('neural-lab')
                  ? 'bg-secondary text-on-secondary'
                  : 'hover:bg-surface-container-high'
              }`}
            >
              <span className="material-symbols-outlined text-sm mr-2 align-middle">neurology</span>
              NEURAL LAB
            </Link>
            <Link
              to={`/cases/${caseId}/reports`}
              className={`px-6 py-3 rounded font-label-sm text-label-sm transition-all whitespace-nowrap ${
                isActiveTab('reports')
                  ? 'bg-secondary text-on-secondary'
                  : 'hover:bg-surface-container-high'
              }`}
            >
              <span className="material-symbols-outlined text-sm mr-2 align-middle">article</span>
              REPORTS
            </Link>
            <Link
              to={`/cases/${caseId}/triage`}
              className={`px-6 py-3 rounded font-label-sm text-label-sm transition-all whitespace-nowrap ${
                isActiveTab('triage')
                  ? 'bg-secondary text-on-secondary'
                  : 'hover:bg-surface-container-high'
              }`}
            >
              <span className="material-symbols-outlined text-sm mr-2 align-middle">detector_status</span>
              TRIAGE
            </Link>
            <Link
              to={`/cases/${caseId}/threat-ops`}
              className={`px-6 py-3 rounded font-label-sm text-label-sm transition-all whitespace-nowrap ${
                isActiveTab('threat-ops')
                  ? 'bg-secondary text-on-secondary'
                  : 'hover:bg-surface-container-high'
              }`}
            >
              <span className="material-symbols-outlined text-sm mr-2 align-middle">target</span>
              THREAT OPS
            </Link>
          </div>
        </GlassPanel>
      </section>

      {/* Content Area */}
      <section className="max-w-7xl">
        <Outlet context={{ caseData, refreshCase }} />
      </section>
    </div>
  )
}

export default CaseWorkspacePage
