import React, { useState, useEffect } from 'react'

interface ActivityLog {
  id: string
  time: string
  message: string
  severity: 'low' | 'medium' | 'high' | 'critical'
}

const STATIC_LOGS = [
  { message: 'Ingesting target APK...', severity: 'low' },
  { message: 'JADX unpacking dex structures...', severity: 'low' },
  { message: 'Scanning Smali patterns via apktool...', severity: 'low' },
  { message: 'Running YARA overlay detection rules...', severity: 'medium' },
  { message: 'Accessibility service hooks identified', severity: 'high' },
  { message: 'C2 network candidate matches extracted', severity: 'high' },
  { message: 'Ghidra analyzing native SO binaries...', severity: 'medium' },
  { message: 'Injecting AI cognition heuristics...', severity: 'low' },
  { message: 'Analysis pipeline completed successfully', severity: 'low' },
  { message: 'Threat dashboard active', severity: 'low' },
]

export const ActivityFeed: React.FC = () => {
  const [logs, setLogs] = useState<ActivityLog[]>([])

  useEffect(() => {
    // Populate initial logs
    const initial = STATIC_LOGS.slice(0, 3).map((l, idx) => ({
      id: Math.random().toString(),
      time: new Date(Date.now() - (3 - idx) * 3000).toLocaleTimeString(),
      ...l
    }))
    setLogs(initial as any)

    // Add log updates periodically
    let step = 3
    const interval = setInterval(() => {
      if (step < STATIC_LOGS.length) {
        const next = {
          id: Math.random().toString(),
          time: new Date().toLocaleTimeString(),
          ...STATIC_LOGS[step]
        }
        setLogs(prev => [next as any, ...prev].slice(0, 15)) // Cap to last 15 logs
        step++
      } else {
        // Recycle logs
        const randomMsg = STATIC_LOGS[random(0, STATIC_LOGS.length - 1)]
        const next = {
          id: Math.random().toString(),
          time: new Date().toLocaleTimeString(),
          ...randomMsg
        }
        setLogs(prev => [next as any, ...prev].slice(0, 15))
      }
    }, 6000)

    return () => clearInterval(interval)
  }, [])

  const random = (min: number, max: number) => {
    return Math.floor(Math.random() * (max - min + 1) + min)
  }

  const getLogColor = (sev: string) => {
    switch (sev) {
      case 'critical':
      case 'high':
        return 'text-error font-bold'
      case 'medium':
        return 'text-warning font-bold'
      default:
        return 'text-on-surface-variant'
    }
  }

  return (
    <div className="w-full bg-surface border border-border rounded-xl p-4 font-mono text-[10px] select-none">
      <div className="flex items-center justify-between border-b border-border pb-2 mb-2">
        <span className="font-bold text-on-surface-variant uppercase tracking-wider flex items-center gap-1">
          <span className="material-symbols-outlined text-xs text-primary animate-pulse">
            sensors
          </span>
          Live Threat Pulse Feed
        </span>
        <span className="text-[9px] text-on-surface-variant opacity-60">
          POLLING LIVE TELEMETRY
        </span>
      </div>

      <div className="h-[70px] overflow-y-auto space-y-1.5 pr-2 hide-scrollbar">
        {logs.map((log) => (
          <div key={log.id} className="flex justify-between items-center gap-4 hover:bg-surface-variant/10 px-1 py-0.5 rounded transition-colors">
            <span className="text-on-surface-variant opacity-45">{log.time}</span>
            <span className={`flex-1 truncate ${getLogColor(log.severity)}`}>
              &gt;&gt; {log.message}
            </span>
            <span className="text-[9px] opacity-45 uppercase tracking-wider">{log.severity}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
export default ActivityFeed
