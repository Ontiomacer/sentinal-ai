import React, { useState } from 'react'
import GlassPanel from '../ui/GlassPanel'
import { neuralApi } from '../../services/neuralApi'

interface ReportPanelProps {
  scanId: string
}

type ReportType = 'executive' | 'technical' | 'ioc' | 'attack' | 'fraud' | 'cognition' | 'banking_fraud'

interface ReportConfig {
  type: ReportType
  label: string
  icon: string
  description: string
}

const REPORT_TYPES: ReportConfig[] = [
  { type: 'banking_fraud', label: 'Fraud Intel Report', icon: 'account_balance', description: 'Comprehensive Banking Fraud Intelligence investigation report (Source: Hybrid AI).' },
  { type: 'executive', label: 'Executive Summary', icon: 'summarize', description: 'High-level security summary for executive review (Source: Static + AI).' },
  { type: 'technical', label: 'Technical Details', icon: 'code', description: 'Technical findings, class heuristics, and extracted strings (Source: Static Analysis).' },
  { type: 'ioc', label: 'Extracted Indicators', icon: 'share', description: 'Extracted URLs, IPs, domains, and hashes for SOC ingestion (Source: Static Analysis).' },
  { type: 'attack', label: 'Predicted Attack Flow', icon: 'grid_view', description: 'Behavior patterns mapped to adversarial tactics (Source: Behavioral Prediction).' },
  { type: 'fraud', label: 'Heuristic Fraud Assessment', icon: 'receipt_long', description: 'Assesses potential credential theft and interception risks (Source: Fraud Reasoning).' },
  { type: 'cognition', label: 'AI-Assisted Narrative', icon: 'psychology', description: 'AI-generated threat narrative detailing potential intent (Source: GenAI Inference).' }
]

export const ReportPanel: React.FC<ReportPanelProps> = ({ scanId }) => {
  const [selectedType, setSelectedType] = useState<ReportType>('banking_fraud')
  const [generating, setGenerating] = useState(false)
  const [reportData, setReportData] = useState<any | null>(null)

  const handleGenerate = async () => {
    setGenerating(true)
    setReportData(null)
    try {
      const res = await neuralApi.getReport(scanId, selectedType)
      setReportData(res.report)
    } catch (e: any) {
      setReportData({ error: `Report compilation failed: ${e.message || 'Connection offline'}` })
    } finally {
      setGenerating(false)
    }
  }

  const downloadReport = () => {
    if (!reportData) return
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(
      JSON.stringify(reportData, null, 2)
    )}`
    const link = document.createElement('a')
    link.setAttribute('href', jsonString)
    link.setAttribute('download', `specter_${selectedType}_report_${scanId.substring(0, 8)}.json`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs select-none h-[500px]">
      
      {/* Types list */}
      <GlassPanel className="p-4 col-span-1 border-border bg-surface-variant/10 flex flex-col justify-between h-full">
        <div className="space-y-2 overflow-y-auto flex-1 pr-1">
          <h4 className="font-bold text-primary mb-3 uppercase tracking-wider">Select Report Type</h4>
          {REPORT_TYPES.map((cfg) => (
            <button
              key={cfg.type}
              onClick={() => {
                setSelectedType(cfg.type)
                setReportData(null)
              }}
              className={`w-full text-left p-3 rounded-lg border transition-colors flex items-start gap-3 ${
                selectedType === cfg.type
                  ? 'border-primary/40 bg-primary/5 text-primary'
                  : 'border-border bg-surface/30 hover:border-border-hover text-on-surface-variant'
              }`}
            >
              <span className="material-symbols-outlined mt-0.5">{cfg.icon}</span>
              <div>
                <span className="font-semibold block text-on-surface">{cfg.label}</span>
                <span className="text-[10px] opacity-60 block mt-0.5">{cfg.description}</span>
              </div>
            </button>
          ))}
        </div>

        <button
          onClick={handleGenerate}
          disabled={generating}
          className="w-full btn-primary py-2.5 mt-4 text-center font-bold flex items-center justify-center gap-1.5 disabled:opacity-50"
        >
          <span className="material-symbols-outlined text-sm">settings_suggest</span>
          {generating ? 'COMPILING REPORT...' : 'COMPILE EXPORT'}
        </button>
      </GlassPanel>

      {/* Preview Pane */}
      <GlassPanel className="p-6 col-span-1 lg:col-span-2 border-border bg-surface-variant/10 flex flex-col h-full overflow-hidden">
        <div className="flex items-center justify-between border-b border-border pb-3 mb-3">
          <h4 className="font-bold text-on-surface uppercase flex items-center gap-1.5">
            <span className="material-symbols-outlined text-sm">visibility</span>
            Report Output Preview
          </h4>
          {reportData && !reportData.error && (
            <button
              onClick={downloadReport}
              className="px-3 py-1.5 rounded bg-success hover:bg-success/90 text-on-success font-bold text-[10px] flex items-center gap-1"
            >
              <span className="material-symbols-outlined text-[12px]">download</span>
              DOWNLOAD JSON
            </button>
          )}
        </div>

        {/* Console Preview Panel */}
        <div className="flex-1 overflow-y-auto bg-surface border border-border rounded-lg p-4 font-mono text-[10px] text-on-surface-variant leading-relaxed select-text">
          {generating ? (
            <div className="h-full flex flex-col items-center justify-center text-center opacity-65">
              <span className="material-symbols-outlined text-4xl block mb-2 animate-spin">
                sync
              </span>
              Bundling forensic artifacts and mapping threat vectors...
            </div>
          ) : reportData ? (
            <pre className="whitespace-pre-wrap font-mono select-text">
              {JSON.stringify(reportData, null, 2)}
            </pre>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center opacity-60">
              <span className="material-symbols-outlined text-4xl block mb-2">description</span>
              Select a report format and click &quot;Compile Export&quot; to inspect compliance diagnostics.
            </div>
          )}
        </div>
      </GlassPanel>
    </div>
  )
}
export default ReportPanel
