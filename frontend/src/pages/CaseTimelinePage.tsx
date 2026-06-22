import { useState, useEffect } from 'react'
import { useOutletContext } from 'react-router-dom'
import GlassPanel from '../components/ui/GlassPanel'
import { CaseResponse, listTimelineEvents, TimelineEvent } from '../services/caseApi'

interface CaseContextType {
  caseData: CaseResponse
  refreshCase: () => void
}

const CaseTimelinePage = () => {
  const { caseData } = useOutletContext<CaseContextType>()
  const [events, setEvents] = useState<TimelineEvent[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchTimeline()
  }, [caseData.id])

  const fetchTimeline = async () => {
    try {
      setLoading(true)
      const data = await listTimelineEvents(caseData.id)
      setEvents(data)
    } catch (error) {
      console.error('Failed to fetch timeline:', error)
    } finally {
      setLoading(false)
    }
  }

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'upload': return 'upload'
      case 'analysis': return 'science'
      case 'report': return 'article'
      case 'note': return 'description'
      case 'finding': return 'warning'
      default: return 'event'
    }
  }

  if (loading) {
    return (
      <div className="fade-in">
        <GlassPanel className="p-12 text-center">
          <span className="material-symbols-outlined text-6xl text-secondary mb-4 block animate-pulse">
            timeline
          </span>
          <p className="text-body-md text-on-surface-variant">Loading timeline...</p>
        </GlassPanel>
      </div>
    )
  }

  return (
    <div className="fade-in">
      {events.length === 0 ? (
        <GlassPanel className="p-12 text-center">
          <span className="material-symbols-outlined text-6xl text-primary mb-6 block">
            timeline
          </span>
          <h2 className="font-title-md text-title-md text-on-surface mb-4">
            Investigation Timeline
          </h2>
          <p className="text-body-md text-on-surface-variant mb-8 max-w-2xl mx-auto">
            Track investigation milestones, evidence uploads, analysis results, and findings
            in chronological order.
          </p>
          <button className="btn-primary inline-flex px-8 py-3">
            <span className="material-symbols-outlined">add</span>
            ADD EVENT
          </button>
        </GlassPanel>
      ) : (
        <div className="space-y-4">
          {events.map((event) => (
            <GlassPanel key={event.id} className="p-6">
              <div className="flex items-start gap-4">
                <div className="flex-shrink-0">
                  <div className="w-12 h-12 rounded-full bg-secondary/20 flex items-center justify-center">
                    <span className="material-symbols-outlined text-secondary">
                      {getEventIcon(event.event_type)}
                    </span>
                  </div>
                </div>
                <div className="flex-1">
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <h3 className="font-title-sm text-title-sm text-on-surface mb-1">
                        {event.title}
                      </h3>
                      <span className="font-label-sm text-label-sm text-on-surface-variant uppercase">
                        {event.event_type}
                      </span>
                    </div>
                    <span className="text-label-sm text-on-surface-variant">
                      {formatDate(event.created_at)}
                    </span>
                  </div>
                  {event.description && (
                    <p className="text-body-md text-on-surface-variant mt-2">
                      {event.description}
                    </p>
                  )}
                </div>
              </div>
            </GlassPanel>
          ))}
        </div>
      )}
    </div>
  )
}

export default CaseTimelinePage
