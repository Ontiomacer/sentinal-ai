import { useEffect, useRef, useState } from 'react'
import GlassPanel from './GlassPanel'

interface TerminalLog {
  timestamp: string
  type: 'success' | 'info' | 'warning' | 'error'
  message: string
}

interface NeuralTerminalProps {
  logs: TerminalLog[]
  title?: string
  height?: string
}

const NeuralTerminal = ({ logs, title = 'Neural Analysis Logs', height = 'h-[600px]' }: NeuralTerminalProps) => {
  const terminalRef = useRef<HTMLDivElement>(null)
  const [cursorVisible, setCursorVisible] = useState(true)

  useEffect(() => {
    // Auto-scroll to bottom when new logs arrive
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [logs])

  useEffect(() => {
    // Cursor blink - subtle and slow
    const interval = setInterval(() => {
      setCursorVisible(prev => !prev)
    }, 800)

    return () => clearInterval(interval)
  }, [])

  const getLogColor = (type: string) => {
    switch (type) {
      case 'success':
        return 'text-tertiary'
      case 'info':
        return 'text-on-surface-variant'
      case 'warning':
        return 'text-secondary'
      case 'error':
        return 'text-error'
      default:
        return 'text-on-surface-variant'
    }
  }

  return (
    <GlassPanel className={`overflow-hidden flex flex-col ${height}`}>
      <div className="bg-surface-container-high px-4 py-3 flex items-center justify-between border-b border-white/10">
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-error/40"></div>
          <div className="w-3 h-3 rounded-full bg-secondary-container/40"></div>
          <div className="w-3 h-3 rounded-full bg-tertiary/40"></div>
        </div>
        <span className="font-label-sm text-label-sm text-on-surface-variant uppercase tracking-widest">
          {title}
        </span>
      </div>
      <div
        ref={terminalRef}
        className="p-6 font-label-sm text-label-sm leading-relaxed overflow-y-auto bg-primary-container/80 flex-grow custom-scrollbar"
      >
        {logs.map((log, index) => (
          <p key={index} className={`${getLogColor(log.type)} mb-2`}>
            {log.timestamp && `[${log.timestamp}] `}
            {log.message}
          </p>
        ))}
        <p className="text-on-surface-variant mt-4">
          {cursorVisible ? '_' : ' '}
        </p>
      </div>
    </GlassPanel>
  )
}

export default NeuralTerminal
