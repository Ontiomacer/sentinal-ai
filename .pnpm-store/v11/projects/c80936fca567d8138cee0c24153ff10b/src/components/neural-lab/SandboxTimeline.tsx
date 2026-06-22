import React, { useState } from 'react'
import GlassPanel from '../ui/GlassPanel'
import { SandboxResponse } from '../../services/neuralApi'

interface SandboxTimelineProps {
  sandboxData: SandboxResponse | null
}

type EventFilter = 'all' | 'network' | 'permission' | 'process' | 'file'

export const SandboxTimeline: React.FC<SandboxTimelineProps> = ({ sandboxData }) => {
  const [filter, setFilter] = useState<EventFilter>('all')

  if (!sandboxData) {
    return (
      <div className="text-center py-20 opacity-60 font-mono text-xs select-none">
        <span className="material-symbols-outlined text-4xl block mb-2 animate-bounce">
          running_with_errors
        </span>
        No static runtime reconstruction records available. Run the analysis pipeline first.
      </div>
    )
  }

  const { events, statistics } = sandboxData.sandbox

  const filteredEvents = events.filter((e) => {
    if (filter === 'all') return true
    return e.type === filter
  })

  const getSeverityColor = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'text-error border-error/20 bg-error/10'
      case 'medium':
        return 'text-warning border-warning/20 bg-warning/10'
      default:
        return 'text-success border-success/20 bg-success/10'
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'network':
        return 'wifi'
      case 'permission':
        return 'shield'
      case 'file':
        return 'description'
      default:
        return 'terminal'
    }
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 font-mono text-xs select-none h-[500px]">
      
      {/* Predicted behavior timeline flow */}
      <GlassPanel className="p-6 col-span-1 lg:col-span-3 border-border bg-surface-variant/5 flex flex-col h-full overflow-hidden">
        
        {/* Source Label */}
        <div className="flex justify-between items-center mb-3">
          <div className="flex items-center gap-2">
            <span className="text-[9px] font-bold text-on-surface-variant bg-surface/80 px-2 py-0.5 rounded border border-border/40 uppercase tracking-tighter">
              Source: Behavioral Prediction
            </span>
            <span className="text-[9px] font-bold text-secondary bg-secondary/5 px-2 py-0.5 rounded border border-secondary/20 uppercase tracking-tighter">
              Confidence: Medium
            </span>
          </div>
        </div>

        {/* Filters bar */}
        <div className="flex items-center gap-1.5 border-b border-border pb-3 mb-3">
          {(['all', 'network', 'permission', 'process', 'file'] as EventFilter[]).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1 rounded-md text-[10px] uppercase font-bold border transition-colors ${
                filter === f
                  ? 'bg-primary text-on-primary border-primary'
                  : 'bg-surface border-border hover:bg-surface-variant text-on-surface-variant'
              }`}
            >
              {f}
            </button>
          ))}
        </div>

        {/* Chronological list */}
        <div className="flex-1 overflow-y-auto space-y-4 pr-1 relative pl-6 border-l border-border/60">
          {filteredEvents.length === 0 ? (
            <div className="text-center py-16 opacity-50">No events found matching filters.</div>
          ) : (
            filteredEvents.map((e, idx) => (
              <div key={idx} className="relative group">
                
                {/* Timeline node dot */}
                <div className="absolute left-[-31px] top-1 w-2.5 h-2.5 rounded-full bg-border border border-surface group-hover:bg-primary transition-colors" />

                <div className="flex items-center justify-between gap-4 mb-1">
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-[12px] text-primary">
                      {getTypeIcon(e.type)}
                    </span>
                    <span className="font-bold text-on-surface">{e.event}</span>
                    <span className="text-[10px] text-on-surface-variant opacity-50">
                      [{e.timestamp}]
                    </span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[8px] font-bold border ${getSeverityColor(e.severity)}`}>
                    {e.severity.toUpperCase()}
                  </span>
                </div>
                <p className="font-semibold text-[11px] text-on-surface-variant mb-0.5">
                  {e.summary}
                </p>
                <p className="text-[10px] text-on-surface-variant opacity-60 leading-relaxed max-w-2xl select-text">
                  {e.detail}
                </p>
              </div>
            ))
          )}
        </div>
      </GlassPanel>

      {/* Reconstruction Metrics Dashboard */}
      <GlassPanel className="p-6 col-span-1 border-border bg-surface-variant/5 flex flex-col justify-between h-full">
        <div className="space-y-4">
          <h4 className="text-xs font-semibold text-primary tracking-wider uppercase flex items-center gap-1.5 border-b border-border pb-2 mb-2">
            <span className="material-symbols-outlined text-sm">psychology</span>
            BEHAVIOR PREDICTION
          </h4>

          <div className="space-y-3 font-mono">
            <div className="flex justify-between items-center text-xs">
              <span className="text-on-surface-variant opacity-70">Simulation Scope:</span>
              <span className="font-bold text-on-surface">{statistics.duration_seconds.toFixed(1)}s</span>
            </div>
            
            <div className="flex justify-between items-center text-xs">
              <span className="text-on-surface-variant opacity-70">Predicted Events:</span>
              <span className="font-bold text-on-surface">{statistics.total_events}</span>
            </div>

            <div className="flex justify-between items-center text-xs">
              <span className="text-on-surface-variant opacity-70">Predicted Criticals:</span>
              <span className="font-bold text-error">{statistics.critical_events}</span>
            </div>

            <div className="flex justify-between items-center text-xs">
              <span className="text-on-surface-variant opacity-70">Predicted Network:</span>
              <span className="font-bold text-on-surface">{statistics.network_requests}</span>
            </div>

            <div className="flex justify-between items-center text-xs">
              <span className="text-on-surface-variant opacity-70">Predicted Risks:</span>
              <span className="font-bold text-error">{statistics.permission_abuses}</span>
            </div>
          </div>
        </div>

        <div className="text-[9px] text-on-surface-variant opacity-50 bg-surface/40 p-2.5 rounded-lg border border-border mt-4">
          Static behavioral prediction only. This is a reconstruction of potential activity based on APK artifacts. No live sandbox execution, runtime telemetry, or real-time permission grants are performed.
        </div>
      </GlassPanel>
    </div>
  )
}
export default SandboxTimeline
