import React, { useState } from 'react'
import { PipelineStage } from '../../hooks/useNeuralLab'

interface AnalysisPipelineProps {
  stages: PipelineStage[]
  pipelineRunning: boolean
}

export const AnalysisPipeline: React.FC<AnalysisPipelineProps> = ({ stages, pipelineRunning }) => {
  const [selectedStage, setSelectedStage] = useState<PipelineStage | null>(null)

  const getStatusColor = (status: PipelineStage['status']) => {
    switch (status) {
      case 'completed':
        return 'border-success text-success bg-success/10 shadow-success/20'
      case 'running':
        return 'border-primary text-primary bg-primary/10 shadow-primary/30 animate-pulse'
      case 'failed':
        return 'border-error text-error bg-error/10 shadow-error/20'
      case 'skipped':
        return 'border-border text-on-surface-variant opacity-40 bg-surface/5'
      default:
        return 'border-border text-on-surface-variant/75 bg-surface/5 hover:border-on-surface-variant/30'
    }
  }

  const getStatusIcon = (status: PipelineStage['status']) => {
    switch (status) {
      case 'completed':
        return <span className="material-symbols-outlined text-sm">check</span>
      case 'running':
        return <span className="material-symbols-outlined text-sm animate-spin">sync</span>
      case 'failed':
        return <span className="material-symbols-outlined text-sm">close</span>
      case 'skipped':
        return <span className="material-symbols-outlined text-sm">forward</span>
      default:
        return <span className="material-symbols-outlined text-sm">hourglass_empty</span>
    }
  }

  return (
    <div className="w-full bg-surface-variant/20 border border-border rounded-xl p-6 backdrop-blur-sm relative select-none">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold text-on-surface-variant opacity-75 tracking-wider uppercase flex items-center gap-1.5 font-mono">
          <span className="material-symbols-outlined text-sm">insights</span>
          Threat Ingestion Pipeline Flow
        </h3>
        {pipelineRunning && (
          <span className="text-xs font-mono text-primary animate-pulse-slow">
            Active extraction pipeline running...
          </span>
        )}
      </div>

      {/* Nodes Container */}
      <div className="relative overflow-x-auto pb-4 hide-scrollbar">
        <div className="flex items-center justify-between min-w-[1000px] gap-2 px-4 relative">
          
          {/* SVG Connector Lines */}
          <div className="absolute left-0 right-0 top-1/2 -translate-y-1/2 h-0.5 bg-border -z-10" />

          {stages.map((stage, idx) => {
            const isSelected = selectedStage?.id === stage.id
            return (
              <div key={stage.id} className="flex flex-col items-center relative z-10 flex-1">
                {/* Node circle */}
                <button
                  onClick={() => setSelectedStage(stage)}
                  className={`w-9 h-9 rounded-full border-2 flex items-center justify-center transition-all duration-300 transform hover:scale-115 ${getStatusColor(
                    stage.status
                  )} ${isSelected ? 'ring-2 ring-primary/40' : ''}`}
                >
                  {getStatusIcon(stage.status)}
                </button>

                {/* Node Label */}
                <span className="text-[10px] font-semibold tracking-tight mt-2 font-mono text-center truncate max-w-[80px] text-on-surface">
                  {stage.name}
                </span>
                
                {/* Stage index connection count */}
                {idx < stages.length - 1 && (
                  <div className={`absolute left-[calc(50%+18px)] right-[-50%] top-4.5 h-0.5 -z-10 transition-colors duration-500 ${
                    stage.status === 'completed' ? 'bg-success/60' : stage.status === 'running' ? 'bg-primary/50' : 'bg-border'
                  }`} />
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Stage Detail Summary */}
      {selectedStage && (
        <div className="mt-4 p-4 border border-border bg-surface/50 rounded-lg animate-fade-in relative">
          <button
            onClick={() => setSelectedStage(null)}
            className="absolute top-3 right-3 text-on-surface-variant hover:text-on-surface text-sm"
          >
            <span className="material-symbols-outlined text-sm">close</span>
          </button>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono font-bold text-primary">{selectedStage.name}</span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${
              selectedStage.status === 'completed' ? 'border-success/30 text-success bg-success/5' : 
              selectedStage.status === 'running' ? 'border-primary/30 text-primary bg-primary/5' : 'border-border text-on-surface-variant'
            }`}>
              {selectedStage.status.toUpperCase()}
            </span>
          </div>
          <p className="text-xs text-on-surface-variant font-mono">{selectedStage.label}</p>
        </div>
      )}
    </div>
  )
}
export default AnalysisPipeline
