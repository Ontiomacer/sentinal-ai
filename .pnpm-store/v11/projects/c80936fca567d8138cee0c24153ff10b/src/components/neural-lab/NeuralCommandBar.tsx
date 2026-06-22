import React from 'react'
import { Investigation } from '../../services/neuralApi'
import ThreatBadge from '../ui/ThreatBadge'

interface NeuralCommandBarProps {
  appName: string
  packageName: string
  versionName: string
  riskScore: number
  severity: string
  pipelineRunning: boolean
  pipelineProgress: number
  investigations: Investigation[]
  activeInvestigation: Investigation | null
  onSwitchInvestigation: (inv: Investigation) => void
  onCreateInvestigation: () => void
  onRunAnalysis: () => void
  onOpenReport: () => void
  aiHealthy: boolean
}

export const NeuralCommandBar: React.FC<NeuralCommandBarProps> = ({
  appName,
  packageName,
  versionName,
  riskScore,
  severity,
  pipelineRunning,
  pipelineProgress,
  investigations,
  activeInvestigation,
  onSwitchInvestigation,
  onCreateInvestigation,
  onRunAnalysis,
  onOpenReport,
  aiHealthy,
}) => {
  return (
    <div className="border-b border-border bg-surface-variant/40 backdrop-blur-md px-6 py-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 select-none">
      {/* APK Metadata Badge */}
      <div className="flex items-center gap-4">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-primary/30 to-secondary/30 flex items-center justify-center border border-primary/20 shadow-glow animate-pulse-slow">
          <span className="material-symbols-outlined text-primary text-xl">neurology</span>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h2 className="font-title-sm text-on-surface font-semibold tracking-tight">{appName}</h2>
            <span className="text-xs text-on-surface-variant opacity-60">v{versionName}</span>
            <ThreatBadge severity={severity as any} label={`${severity} (${riskScore}/100)`} />
          </div>
          <p className="text-xs font-mono text-on-surface-variant opacity-50">{packageName}</p>
        </div>
      </div>

      {/* Pipeline Progress Indicator */}
      {pipelineRunning && (
        <div className="flex-1 max-w-xs px-4">
          <div className="flex justify-between items-center text-xs mb-1">
            <span className="text-primary font-semibold animate-pulse">Running Ingest...</span>
            <span className="text-on-surface-variant font-mono">{pipelineProgress}%</span>
          </div>
          <div className="w-full bg-border rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-gradient-to-r from-primary via-secondary to-primary h-full rounded-full transition-all duration-300 shadow-glow"
              style={{ width: `${pipelineProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* Workspace / Actions Bar */}
      <div className="flex items-center gap-3 w-full md:w-auto justify-end">
        {/* Connection states */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-border bg-surface-variant/20 text-[10px] uppercase font-bold tracking-tighter">
            <span className={`w-1.5 h-1.5 rounded-full ${aiHealthy ? 'bg-success animate-pulse' : 'bg-warning animate-glow-breathe'}`} />
            <span className="text-on-surface-variant opacity-75 font-mono">{aiHealthy ? 'AI ONLINE' : 'AI STANDBY'}</span>
          </div>
          
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-border bg-surface-variant/20 text-[10px] uppercase font-bold tracking-tighter">
            <span className="w-1.5 h-1.5 rounded-full bg-success" />
            <span className="text-on-surface-variant opacity-75 font-mono">STATIC OK</span>
          </div>
        </div>

        {/* Investigation selector */}
        <div className="flex items-center gap-2">
          <select
            className="bg-surface border border-border text-on-surface rounded-md text-xs px-3 py-1.5 focus:outline-none focus:border-primary font-mono cursor-pointer"
            value={activeInvestigation?.id || ''}
            onChange={(e) => {
              const selected = investigations.find((inv) => inv.id === e.target.value)
              if (selected) onSwitchInvestigation(selected)
            }}
          >
            {investigations.length === 0 ? (
              <option value="">No Active Investigations</option>
            ) : (
              investigations.map((inv) => (
                <option key={inv.id} value={inv.id}>
                  {inv.title}
                </option>
              ))
            )}
          </select>
          <button
            onClick={onCreateInvestigation}
            className="p-1.5 rounded-md border border-border hover:bg-surface-variant text-on-surface-variant hover:text-on-surface transition-colors"
            title="New Investigation Session"
          >
            <span className="material-symbols-outlined text-sm block">add</span>
          </button>
        </div>

        {/* Action Buttons */}
        <button
          onClick={onRunAnalysis}
          disabled={pipelineRunning}
          className={`btn-primary px-4 py-1.5 text-xs flex items-center gap-2 ${pipelineRunning ? 'opacity-50 cursor-not-allowed' : ''}`}
        >
          <span className="material-symbols-outlined text-sm">play_arrow</span>
          {pipelineRunning ? 'ANALYZING...' : 'RUN PIPELINE'}
        </button>

        <button
          onClick={onOpenReport}
          className="btn-secondary px-4 py-1.5 text-xs flex items-center gap-2 border border-border bg-surface-variant/30 hover:bg-surface-variant"
        >
          <span className="material-symbols-outlined text-sm">description</span>
          EXPORT REPORT
        </button>
      </div>
    </div>
  )
}
export default NeuralCommandBar
