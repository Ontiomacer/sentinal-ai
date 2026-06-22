/**
 * DYNAMIC INVESTIGATION TIMELINE
 * Chronological timeline of runtime events
 * Shows the investigation flow from APK deployment to analysis completion
 */

import React from 'react'

interface Props {
  events: any[]
}

interface TimelineEvent {
  timestamp: Date
  type: 'system' | 'activity' | 'service' | 'permission' | 'network' | 'threat'
  title: string
  description?: string
  severity?: 'info' | 'warning' | 'critical'
}

const DynamicInvestigationTimeline: React.FC<Props> = ({ events }) => {
  const timelineEvents: TimelineEvent[] = events.map((event) => ({
    timestamp: event.timestamp ? new Date(event.timestamp) : new Date(),
    type: event.type || 'system',
    title: event.title || event.message || 'Runtime Event',
    description: event.description,
    severity: event.severity || 'info'
  }))

  const getEventIcon = (type: string) => {
    switch (type) {
      case 'system': return 'settings'
      case 'activity': return 'window'
      case 'service': return 'play_circle'
      case 'permission': return 'security'
      case 'network': return 'cloud'
      case 'threat': return 'warning'
      default: return 'circle'
    }
  }

  const getEventColor = (severity?: string) => {
    switch (severity) {
      case 'critical': return 'border-red-500 bg-red-900/20'
      case 'warning': return 'border-yellow-500 bg-yellow-900/20'
      case 'info': return 'border-green-500 bg-green-900/20'
      default: return 'border-gray-500 bg-gray-900/20'
    }
  }

  const getIconColor = (severity?: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400'
      case 'warning': return 'text-yellow-400'
      case 'info': return 'text-green-400'
      default: return 'text-gray-400'
    }
  }

  const formatTime = (date: Date) => {
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffSec = Math.floor(diffMs / 1000)
    const diffMin = Math.floor(diffSec / 60)
    
    if (diffMin < 1) return `${diffSec}s ago`
    if (diffMin < 60) return `${diffMin}m ago`
    return date.toLocaleTimeString()
  }

  return (
    <div className="h-full bg-[#0f1419] border border-green-900/30 rounded flex flex-col overflow-hidden">
      <div className="h-10 bg-[#1a1f2e] border-b border-green-900/30 flex items-center px-4">
        <span className="material-symbols-outlined text-sm text-green-400 mr-2">timeline</span>
        <span className="font-mono text-xs uppercase tracking-wider text-gray-400">
          Investigation Timeline
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-3">
        {timelineEvents.length === 0 ? (
          <div className="h-full flex items-center justify-center">
            <div className="text-center">
              <span className="material-symbols-outlined text-3xl text-gray-700 mb-2 block">
                schedule
              </span>
              <p className="text-xs font-mono text-gray-600">No events recorded</p>
            </div>
          </div>
        ) : (
          <div className="space-y-3 relative">
            {/* Timeline Line */}
            <div className="absolute left-[7px] top-0 bottom-0 w-px bg-green-900/30"></div>

            {timelineEvents.map((event, idx) => (
              <div key={idx} className="relative pl-6">
                {/* Timeline Dot */}
                <div className={`absolute left-0 top-2 w-4 h-4 rounded-full border-2 ${
                  event.severity === 'critical' ? 'border-red-500 bg-red-900/50' :
                  event.severity === 'warning' ? 'border-yellow-500 bg-yellow-900/50' :
                  'border-green-500 bg-green-900/50'
                }`}></div>

                {/* Event Card */}
                <div className={`p-2 rounded border ${getEventColor(event.severity)}`}>
                  <div className="flex items-start gap-2">
                    <span className={`material-symbols-outlined text-sm ${getIconColor(event.severity)}`}>
                      {getEventIcon(event.type)}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-mono text-white">{event.title}</div>
                      {event.description && (
                        <div className="text-[10px] font-mono text-gray-400 mt-0.5">
                          {event.description}
                        </div>
                      )}
                      <div className="text-[10px] font-mono text-gray-600 mt-1">
                        {formatTime(event.timestamp)}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Status */}
      {timelineEvents.length > 0 && (
        <div className="h-8 bg-[#1a1f2e] border-t border-green-900/30 flex items-center justify-between px-4">
          <div className="text-[10px] font-mono text-gray-600">
            {timelineEvents.length} events
          </div>
          <div className="text-[10px] font-mono text-gray-600">
            Live tracking
          </div>
        </div>
      )}
    </div>
  )
}

export default DynamicInvestigationTimeline
