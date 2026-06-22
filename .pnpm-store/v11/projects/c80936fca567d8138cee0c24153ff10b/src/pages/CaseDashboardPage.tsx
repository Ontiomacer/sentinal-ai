import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useUser } from '@clerk/clerk-react'
import GlassPanel from '../components/ui/GlassPanel'
import ThreatBadge from '../components/ui/ThreatBadge'
import { listCases, CaseResponse, listTimelineEvents, TimelineEvent } from '../services/caseApi'

const CaseDashboardPage = () => {
  const { user } = useUser()
  const [cases, setCases] = useState<CaseResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<'all' | 'active' | 'archived'>('active')
  const [recentEvents, setRecentEvents] = useState<(TimelineEvent & { caseName?: string })[]>([])

  useEffect(() => {
    fetchCases()
  }, [filter])

  const fetchCases = async () => {
    try {
      setLoading(true)
      const status = filter === 'all' ? undefined : filter
      const data = await listCases(status)
      setCases(data)

      // Fetch recent timeline events from first 3 cases
      if (data.length > 0) {
        const eventPromises = data.slice(0, 3).map(async (c) => {
          try {
            const events = await listTimelineEvents(c.id)
            return events.slice(0, 5).map((e) => ({ ...e, caseName: c.name }))
          } catch { return [] }
        })
        const allEvents = (await Promise.all(eventPromises)).flat()
        allEvents.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
        setRecentEvents(allEvents.slice(0, 10))
      }
    } catch (error) {
      console.error('Failed to fetch cases:', error)
    } finally {
      setLoading(false)
    }
  }

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  }

  const formatTime = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })
  }

  const activeCount = cases.filter(c => c.status === 'active').length
  const highPriorityCount = cases.filter(c => c.severity === 'critical' || c.severity === 'high').length
  const archivedCount = cases.filter(c => c.status === 'archived').length
  const evidenceCount = cases.reduce((sum, c) => sum + c.evidence_count, 0)
  const timelineCount = cases.reduce((sum, c) => sum + c.timeline_count, 0)

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'border-l-red-500 hover:shadow-red-500/10'
      case 'high': return 'border-l-amber-500 hover:shadow-amber-500/10'
      case 'medium': return 'border-l-blue-400 hover:shadow-blue-400/10'
      case 'low': return 'border-l-emerald-400 hover:shadow-emerald-400/10'
      default: return 'border-l-gray-400'
    }
  }

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'upload': return 'upload_file'
      case 'analysis': return 'analytics'
      case 'report': return 'description'
      case 'note': return 'edit_note'
      case 'finding': return 'policy'
      default: return 'circle'
    }
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
            Loading Case Vault
          </p>
          <p className="font-label-sm text-label-sm text-on-surface-variant font-mono">
            [ Accessing Investigation Database ]
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="container-padding fade-in">
      {/* ════════════ CSI Welcome Banner ════════════ */}
      <section className="mb-8 max-w-7xl">
        <div className="csi-welcome-banner rounded-xl p-6 md:p-8 relative overflow-hidden">
          <div className="neural-scanline absolute inset-0 pointer-events-none opacity-30" />
          <div className="relative z-10">
            <div className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-6">
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <span className="material-symbols-outlined text-secondary text-lg">shield</span>
                  <span className="font-mono text-[10px] tracking-[0.3em] uppercase text-on-surface-variant/60">
                    Forensic Workstation • {new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
                  </span>
                </div>
                <h1 className="font-display-xl text-display-xl tracking-tighter text-on-surface leading-none mb-3">
                  CASE VAULT
                </h1>
                <p className="font-body-md text-body-md text-on-surface-variant/70 max-w-2xl leading-relaxed">
                  Welcome back, <span className="text-secondary font-semibold">{user?.firstName || user?.username || 'Analyst'}</span>.
                  {activeCount > 0
                    ? ` You have ${activeCount} active investigation${activeCount > 1 ? 's' : ''} across ${evidenceCount} evidence items.`
                    : ' No active investigations. Create a new case to begin.'}
                </p>
              </div>

              {/* Quick Stats */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 lg:gap-6">
                {[
                  { label: 'ACTIVE', value: activeCount, color: 'text-secondary' },
                  { label: 'PRIORITY', value: highPriorityCount, color: 'text-red-400' },
                  { label: 'EVIDENCE', value: evidenceCount, color: 'text-blue-400' },
                  { label: 'EVENTS', value: timelineCount, color: 'text-emerald-400' },
                ].map(stat => (
                  <div key={stat.label} className="text-center lg:text-left border-l border-white/10 pl-3">
                    <span className="font-mono text-[9px] tracking-[0.2em] uppercase text-on-surface-variant/50 block mb-0.5">
                      {stat.label}
                    </span>
                    <span className={`font-display-lg text-2xl font-bold ${stat.color}`}>
                      {stat.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ════════════ Action Bar ════════════ */}
      <section className="mb-8 max-w-7xl">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex gap-1.5 overflow-x-auto">
            {(['active', 'archived', 'all'] as const).map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-5 py-2.5 rounded font-label-sm text-label-sm transition-all whitespace-nowrap ${
                  filter === f
                    ? 'bg-secondary text-on-secondary'
                    : 'glass-panel hover:border-secondary/40 text-on-surface-variant'
                }`}
              >
                {f.toUpperCase()}
                {f === 'active' && activeCount > 0 && (
                  <span className="ml-2 px-1.5 py-0.5 bg-white/15 rounded text-[10px]">{activeCount}</span>
                )}
              </button>
            ))}
          </div>

          <div className="flex gap-2">
            <Link
              to="/cases/new"
              className="btn-primary inline-flex items-center justify-center gap-2 px-6 py-2.5 w-auto"
            >
              <span className="material-symbols-outlined text-lg">add</span>
              NEW CASE
            </Link>
          </div>
        </div>
      </section>

      {/* ════════════ Case Grid ════════════ */}
      <section className="mb-10 max-w-7xl">
        {cases.length === 0 ? (
          <GlassPanel className="p-12 text-center">
            <span className="material-symbols-outlined text-6xl text-on-surface-variant mb-6 block opacity-30">
              folder_off
            </span>
            <h2 className="font-title-md text-title-md text-on-surface mb-4">
              No Cases Found
            </h2>
            <p className="text-body-md text-on-surface-variant mb-8 max-w-2xl mx-auto">
              {filter === 'active'
                ? 'No active investigations. Create a new case to begin forensic analysis.'
                : filter === 'archived'
                ? 'No archived cases found.'
                : 'No cases in the system. Start your first investigation.'}
            </p>
            <Link to="/cases/new" className="btn-primary inline-flex px-8 py-3 w-auto mx-auto">
              <span className="material-symbols-outlined">add</span>
              CREATE FIRST CASE
            </Link>
          </GlassPanel>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {cases.map((caseItem) => (
              <Link
                key={caseItem.id}
                to={`/cases/${caseItem.id}`}
                className={`case-card-csi group ${getSeverityColor(caseItem.severity)}`}
              >
                {/* Header Row */}
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className="font-mono text-[11px] text-on-surface-variant/70 tracking-wider">
                        {caseItem.id}
                      </span>
                      <ThreatBadge
                        severity={caseItem.severity.toUpperCase() as any}
                        label={caseItem.severity}
                      />
                    </div>
                    <h3 className="font-title-md text-title-md text-on-surface mb-1 group-hover:text-secondary transition-colors truncate">
                      {caseItem.name}
                    </h3>
                  </div>
                  <span className="material-symbols-outlined text-on-surface-variant/30 group-hover:text-secondary transition-all group-hover:translate-x-0.5 mt-1">
                    arrow_forward
                  </span>
                </div>

                {/* Meta */}
                <div className="flex gap-4 mb-3 text-body-sm text-on-surface-variant/60">
                  {caseItem.client_name && (
                    <span className="flex items-center gap-1">
                      <span className="material-symbols-outlined text-xs">business</span>
                      {caseItem.client_name}
                    </span>
                  )}
                  <span className="flex items-center gap-1">
                    <span className="material-symbols-outlined text-xs">person</span>
                    {caseItem.investigator}
                  </span>
                </div>

                {caseItem.description && (
                  <p className="text-body-sm text-on-surface-variant/50 mb-3 line-clamp-2 leading-relaxed">
                    {caseItem.description}
                  </p>
                )}

                {/* Stats Bar */}
                <div className="flex gap-3 mb-3 pt-3 border-t border-white/5">
                  {[
                    { icon: 'description', val: caseItem.evidence_count, label: 'Evidence' },
                    { icon: 'hub', val: caseItem.entity_count, label: 'Entities' },
                    { icon: 'timeline', val: caseItem.timeline_count, label: 'Events' },
                    { icon: 'edit_note', val: caseItem.note_count, label: 'Notes' },
                  ].map(s => (
                    <div key={s.label} className="flex items-center gap-1 text-on-surface-variant/50" title={s.label}>
                      <span className="material-symbols-outlined text-xs">{s.icon}</span>
                      <span className="font-mono text-[11px]">{s.val}</span>
                    </div>
                  ))}
                </div>

                {/* Tags */}
                {caseItem.tags && caseItem.tags.length > 0 && (
                  <div className="flex gap-1.5 flex-wrap mb-3">
                    {caseItem.tags.slice(0, 3).map((tag, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 bg-white/5 text-on-surface-variant/60 font-mono text-[10px] rounded tracking-wide uppercase"
                      >
                        {tag}
                      </span>
                    ))}
                    {caseItem.tags.length > 3 && (
                      <span className="px-2 py-0.5 text-on-surface-variant/40 font-mono text-[10px]">
                        +{caseItem.tags.length - 3}
                      </span>
                    )}
                  </div>
                )}

                {/* Footer */}
                <div className="flex items-center justify-between text-[10px] text-on-surface-variant/40 pt-3 border-t border-white/5">
                  <span className="font-mono">{formatDate(caseItem.created_at)}</span>
                  <span className={`px-2 py-0.5 rounded font-mono tracking-wider uppercase ${
                    caseItem.status === 'active'
                      ? 'bg-secondary/10 text-secondary/80'
                      : 'bg-white/5 text-on-surface-variant/50'
                  }`}>
                    {caseItem.status}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </section>

      {/* ════════════ Recent Activity Feed ════════════ */}
      {recentEvents.length > 0 && (
        <section className="max-w-7xl mb-section-gap">
          <div className="flex items-center gap-2 mb-4">
            <span className="material-symbols-outlined text-secondary text-lg">bolt</span>
            <h2 className="font-label-sm text-label-sm tracking-widest uppercase text-on-surface-variant/60">
              Recent Activity
            </h2>
          </div>
          <GlassPanel className="p-4">
            <div className="space-y-2 max-h-64 overflow-y-auto custom-scrollbar">
              {recentEvents.map((event, idx) => (
                <div
                  key={event.id || idx}
                  className="flex items-start gap-3 px-3 py-2 rounded hover:bg-white/[0.03] transition-colors"
                >
                  <span className="material-symbols-outlined text-sm text-on-surface-variant/40 mt-0.5">
                    {getEventIcon(event.event_type)}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="font-label-sm text-label-sm text-on-surface truncate">
                        {event.title}
                      </span>
                      {event.caseName && (
                        <span className="font-mono text-[9px] text-on-surface-variant/40 tracking-wider uppercase shrink-0">
                          {event.caseName}
                        </span>
                      )}
                    </div>
                    {event.description && (
                      <p className="text-body-sm text-on-surface-variant/50 truncate">
                        {event.description}
                      </p>
                    )}
                  </div>
                  <span className="font-mono text-[10px] text-on-surface-variant/30 shrink-0">
                    {formatTime(event.created_at)}
                  </span>
                </div>
              ))}
            </div>
          </GlassPanel>
        </section>
      )}

      {/* ════════════ Bottom Stats ════════════ */}
      <section className="max-w-7xl">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { icon: 'folder', color: 'text-secondary', value: activeCount, label: 'ACTIVE CASES' },
            { icon: 'warning', color: 'text-red-400', value: highPriorityCount, label: 'HIGH PRIORITY' },
            { icon: 'inventory_2', color: 'text-amber-400', value: archivedCount, label: 'ARCHIVED' },
            { icon: 'description', color: 'text-blue-400', value: evidenceCount, label: 'TOTAL EVIDENCE' },
          ].map(stat => (
            <GlassPanel key={stat.label} className="p-5">
              <div className="flex items-center justify-between mb-2">
                <span className={`material-symbols-outlined text-2xl ${stat.color}`}>{stat.icon}</span>
                <span className={`font-display-xl text-xl font-bold ${stat.color}`}>{stat.value}</span>
              </div>
              <h3 className="font-mono text-[10px] tracking-[0.15em] text-on-surface-variant/50 uppercase">
                {stat.label}
              </h3>
            </GlassPanel>
          ))}
        </div>
      </section>
    </div>
  )
}

export default CaseDashboardPage
