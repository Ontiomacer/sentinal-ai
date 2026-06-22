import { useState, useEffect } from 'react'
import { mcpApi, SystemHealthStatus } from '../../services/mcpApi'

const POLL_INTERVAL = 30_000 // 30 seconds

const SystemHealthStrip = () => {
  const [health, setHealth] = useState<SystemHealthStatus | null>(null)
  const [uptime, setUptime] = useState(0)
  const [clock, setClock] = useState(new Date())

  useEffect(() => {
    const fetchHealth = () => {
      mcpApi.getSystemHealth().then(setHealth).catch(() => {})
    }
    fetchHealth()
    const id = setInterval(fetchHealth, POLL_INTERVAL)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    const id = setInterval(() => {
      setClock(new Date())
      setUptime((u) => u + 1)
    }, 1000)
    return () => clearInterval(id)
  }, [])

  const formatUptime = (seconds: number) => {
    const h = Math.floor(seconds / 3600)
    const m = Math.floor((seconds % 3600) / 60)
    const s = seconds % 60
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
  }

  const StatusDot = ({ online, label, detail }: { online: boolean; label: string; detail?: string }) => (
    <div className="flex items-center gap-1.5 px-3 py-1" title={detail}>
      <span className={`inline-block w-1.5 h-1.5 rounded-full ${online ? 'bg-emerald-400 status-pulse' : 'bg-red-400'}`} />
      <span className="font-mono text-[10px] tracking-widest uppercase text-inherit opacity-80">
        {label}
      </span>
    </div>
  )

  return (
    <div className="system-health-strip">
      <div className="flex items-center gap-0.5 divide-x divide-white/10">
        <StatusDot
          online={health?.backend.healthy ?? false}
          label={`Backend ${health?.backend.healthy ? 'Online' : 'Offline'}`}
        />
        <StatusDot
          online={health?.ghidra.connected ?? false}
          label={`Ghidra MCP ${health?.ghidra.connected ? `(${health.ghidra.tools_count} tools)` : 'Offline'}`}
          detail={health?.ghidra.latency_ms ? `${health.ghidra.latency_ms}ms` : undefined}
        />
        <StatusDot
          online={health?.ai.ollama_running ?? false}
          label={`AI Engine ${health?.ai.ollama_running ? 'Active' : 'Offline'}`}
        />
        <StatusDot
          online={health?.database.status === 'online'}
          label="Database"
        />
      </div>
      <div className="flex items-center gap-4">
        <span className="font-mono text-[10px] tracking-widest text-on-surface-variant/60 uppercase">
          Session {formatUptime(uptime)}
        </span>
        <span className="font-mono text-[10px] tracking-wider text-on-surface-variant/50">
          {clock.toLocaleTimeString('en-US', { hour12: false })}
        </span>
      </div>
    </div>
  )
}

export default SystemHealthStrip
