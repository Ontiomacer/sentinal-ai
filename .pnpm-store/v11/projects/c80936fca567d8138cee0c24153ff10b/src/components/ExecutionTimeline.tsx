import React from 'react';

interface ExecutionEvent {
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'success';
  message: string;
  source: string;
}

interface ExecutionTimelineProps {
  events: ExecutionEvent[];
  maxVisible?: number;
}

/**
 * Execution Timeline Visualization
 * 
 * Renders a timeline of execution events showing:
 * - Function invocations
 * - API calls
 * - Memory allocations
 * - Suspicious events highlighted
 */
export const ExecutionTimeline: React.FC<ExecutionTimelineProps> = ({
  events,
  maxVisible = 50
}) => {
  if (events.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-on-surface-variant/40">
        <div className="text-center">
          <span className="material-symbols-outlined text-[48px] mb-2 opacity-20">timeline</span>
          <p className="text-[11px] font-mono uppercase tracking-[0.18em]">No execution events</p>
        </div>
      </div>
    );
  }

  const displayEvents = events.slice(0, maxVisible);
  const threatLevel = (level: string): 'critical' | 'high' | 'medium' | 'low' => {
    if (level === 'error') return 'critical';
    if (level === 'warn') return 'high';
    if (level === 'success') return 'low';
    return 'medium';
  };

  const threatColor = (level: 'critical' | 'high' | 'medium' | 'low'): string => {
    switch (level) {
      case 'critical': return 'from-error/20 to-error/5 border-error/30';
      case 'high': return 'from-tertiary/20 to-tertiary/5 border-tertiary/30';
      case 'medium': return 'from-primary/20 to-primary/5 border-primary/30';
      case 'low': return 'from-success/20 to-success/5 border-success/30';
    }
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 overflow-y-auto space-y-2 p-3">
        {displayEvents.map((event, idx) => {
          const threat = threatLevel(event.level);
          return (
            <div
              key={idx}
              className={`p-2 rounded-lg border bg-gradient-to-r ${threatColor(threat)} hover:shadow-md transition-shadow`}
            >
              <div className="flex gap-2 items-start text-[9px]">
                <span className="text-on-surface-variant opacity-40 shrink-0 w-12">
                  [{event.timestamp}]
                </span>
                <span className={`font-bold uppercase tracking-tighter shrink-0 w-12 ${
                  event.level === 'error' ? 'text-error' :
                  event.level === 'warn' ? 'text-tertiary' :
                  event.level === 'success' ? 'text-success' :
                  'text-primary'
                }`}>
                  {event.level}
                </span>
                <span className="text-on-surface-variant/50 shrink-0">
                  [{event.source}]
                </span>
                <span className="text-on-surface flex-1">{event.message}</span>
              </div>
            </div>
          );
        })}
      </div>

      {events.length > maxVisible && (
        <div className="border-t border-white/10 p-2 text-center text-[9px] text-on-surface-variant/50">
          +{events.length - maxVisible} earlier events...
        </div>
      )}
    </div>
  );
};

export default ExecutionTimeline;
