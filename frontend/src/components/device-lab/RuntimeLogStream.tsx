/**
 * RUNTIME LOG STREAM
 * Real-time logcat viewer with filtering
 * Backend Integration: WebSocket /ws/device-lab/logcat
 */

import React, { useState, useEffect, useRef } from 'react'

interface Props {
  device: any
  isRunning: boolean
}

interface LogEntry {
  timestamp: string
  pid: string
  tid: string
  level: 'V' | 'D' | 'I' | 'W' | 'E' | 'F'
  tag: string
  message: string
}

const RuntimeLogStream: React.FC<Props> = ({ device, isRunning }) => {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [filter, setFilter] = useState<string>('')
  const [levelFilter, setLevelFilter] = useState<string[]>(['E', 'W', 'I'])
  const [autoScroll, setAutoScroll] = useState(true)
  const logContainerRef = useRef<HTMLDivElement>(null)

  // Real WebSocket log streaming
  useEffect(() => {
    if (!device || !isRunning) return

    let ws: WebSocket | null = null

    const connectWebSocket = () => {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const wsUrl = `${protocol}//${window.location.host}/api/v1/device-lab/ws/logcat?serial=${device.serial}`
        
        ws = new WebSocket(wsUrl)

        ws.onopen = () => {
          console.log('Logcat WebSocket connected')
        }

        ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data)
            
            if (message.type === 'log' && message.data) {
              setLogs(prev => [...prev.slice(-99), message.data]) // Keep last 100
            }
          } catch (error) {
            console.error('Failed to parse log message:', error)
          }
        }

        ws.onerror = (error) => {
          console.error('WebSocket error:', error)
        }

        ws.onclose = () => {
          console.log('Logcat WebSocket closed')
        }
      } catch (error) {
        console.error('Failed to connect WebSocket:', error)
      }
    }

    connectWebSocket()

    return () => {
      if (ws) {
        ws.close()
      }
    }
  }, [device, isRunning])

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [logs, autoScroll])

  const toggleLevelFilter = (level: string) => {
    setLevelFilter(prev => 
      prev.includes(level) 
        ? prev.filter(l => l !== level)
        : [...prev, level]
    )
  }

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'E': return 'text-red-400'
      case 'W': return 'text-yellow-400'
      case 'I': return 'text-blue-400'
      case 'D': return 'text-gray-400'
      case 'V': return 'text-gray-600'
      default: return 'text-gray-500'
    }
  }

  const filteredLogs = logs.filter(log => {
    if (!levelFilter.includes(log.level)) return false
    if (filter && !log.message.toLowerCase().includes(filter.toLowerCase()) && 
        !log.tag.toLowerCase().includes(filter.toLowerCase())) {
      return false
    }
    return true
  })

  const clearLogs = () => setLogs([])

  return (
    <div className="h-full bg-[#0f1419] border border-green-900/30 rounded flex flex-col overflow-hidden">
      {/* Controls */}
      <div className="h-12 bg-[#1a1f2e] border-b border-green-900/30 flex items-center gap-3 px-4">
        {/* Level Filters */}
        <div className="flex items-center gap-1">
          {['E', 'W', 'I', 'D', 'V'].map(level => (
            <button
              key={level}
              onClick={() => toggleLevelFilter(level)}
              className={`px-2 py-1 rounded text-xs font-mono transition-colors ${
                levelFilter.includes(level)
                  ? 'bg-green-500/20 border border-green-500/50 text-green-400'
                  : 'bg-[#0f1419] border border-green-900/30 text-gray-600'
              }`}
            >
              {level}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="flex-1 flex items-center gap-2">
          <span className="material-symbols-outlined text-sm text-gray-600">search</span>
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter logs..."
            className="flex-1 bg-transparent text-xs font-mono text-gray-400 outline-none placeholder-gray-700"
          />
        </div>

        {/* Auto-scroll */}
        <button
          onClick={() => setAutoScroll(!autoScroll)}
          className={`px-2 py-1 rounded text-xs font-mono transition-colors ${
            autoScroll
              ? 'bg-green-500/20 border border-green-500/50 text-green-400'
              : 'bg-[#0f1419] border border-green-900/30 text-gray-600'
          }`}
        >
          <span className="material-symbols-outlined text-sm">arrow_downward</span>
        </button>

        {/* Clear */}
        <button
          onClick={clearLogs}
          className="px-2 py-1 bg-[#0f1419] border border-green-900/30 hover:border-red-700 rounded text-xs font-mono text-gray-400 hover:text-red-400 transition-colors"
        >
          <span className="material-symbols-outlined text-sm">clear_all</span>
        </button>

        {/* Log Count */}
        <div className="text-xs font-mono text-gray-600">
          {filteredLogs.length} / {logs.length}
        </div>
      </div>

      {/* Log Display */}
      <div 
        ref={logContainerRef}
        className="flex-1 overflow-y-auto font-mono text-xs"
      >
        {!device || !isRunning ? (
          <div className="h-full flex items-center justify-center">
            <div className="text-center">
              <span className="material-symbols-outlined text-3xl text-gray-700 mb-2 block">
                terminal
              </span>
              <p className="text-xs font-mono text-gray-600">
                {!device ? 'No device connected' : 'Launch APK to start logging'}
              </p>
            </div>
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="h-full flex items-center justify-center">
            <div className="text-center">
              <span className="material-symbols-outlined text-3xl text-gray-700 mb-2 block">
                filter_alt_off
              </span>
              <p className="text-xs font-mono text-gray-600">No logs match filter</p>
            </div>
          </div>
        ) : (
          <div className="p-2 space-y-0.5">
            {filteredLogs.map((log, idx) => (
              <div
                key={idx}
                className="flex items-start gap-2 hover:bg-[#1a1f2e] px-2 py-1 rounded text-[10px] leading-relaxed"
              >
                <span className="text-gray-700 shrink-0">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
                <span className={`shrink-0 font-bold ${getLevelColor(log.level)}`}>
                  {log.level}
                </span>
                <span className="text-gray-600 shrink-0">{log.pid}/{log.tid}</span>
                <span className="text-cyan-400 shrink-0">{log.tag}:</span>
                <span className="text-gray-400 flex-1">{log.message}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Status Bar */}
      {device && isRunning && (
        <div className="h-8 bg-[#1a1f2e] border-t border-green-900/30 flex items-center justify-between px-4">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
            <span className="text-[10px] font-mono text-green-400">
              Streaming logcat
            </span>
          </div>
          <div className="text-[10px] font-mono text-gray-600">
            Backend: adb logcat -v threadtime
          </div>
        </div>
      )}
    </div>
  )
}

export default RuntimeLogStream
