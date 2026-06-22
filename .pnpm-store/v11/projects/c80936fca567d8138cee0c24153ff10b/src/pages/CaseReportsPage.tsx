import { useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import GlassPanel from '../components/ui/GlassPanel'
import {
  CaseReportItem,
  CaseReportInventory,
  CaseResponse,
  generateCaseReport,
  listCaseReports,
  getCaseReportContent
} from '../services/caseApi'

interface CaseContextType {
  caseData: CaseResponse
  refreshCase: () => void
}

const reportTemplates = [
  {
    type: 'executive' as const,
    icon: 'article',
    title: 'Executive Summary',
    description: 'Case status, evidence posture, and management-ready investigation snapshot.'
  },
  {
    type: 'technical' as const,
    icon: 'code',
    title: 'Technical Report',
    description: 'Evidence hashes, analysis state, file paths, and technical inventory.'
  },
  {
    type: 'timeline' as const,
    icon: 'timeline',
    title: 'Timeline Export',
    description: 'Chronological chain of custody and investigation events.'
  },
  {
    type: 'ioc' as const,
    icon: 'warning',
    title: 'IOC Export',
    description: 'URLs, domains, IP addresses, and entities found in real case data.'
  }
]

const formatBytes = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

// Simple custom markdown renderer to display report text beautifully
const SimpleMarkdownRenderer = ({ text }: { text: string }) => {
  const lines = text.split('\n')
  return (
    <div className="space-y-4 font-mono text-sm text-on-surface-variant/90 leading-relaxed">
      {lines.map((line, idx) => {
        if (line.startsWith('# ')) {
          return <h1 key={idx} className="text-xl font-bold text-primary border-b border-white/10 pb-2 mt-6 uppercase tracking-wider">{line.slice(2)}</h1>
        }
        if (line.startsWith('## ')) {
          return <h2 key={idx} className="text-lg font-bold text-secondary mt-4 uppercase tracking-wide">{line.slice(3)}</h2>
        }
        if (line.startsWith('### ')) {
          return <h3 key={idx} className="text-base font-bold text-tertiary mt-3 uppercase">{line.slice(4)}</h3>
        }
        if (line.startsWith('- ')) {
          // Parse bold text **bold**
          const parts = line.slice(2).split('**')
          return (
            <div key={idx} className="flex items-start gap-2 pl-4">
              <span className="text-secondary select-none">•</span>
              <span>
                {parts.map((part, i) => i % 2 === 1 ? <strong key={i} className="text-on-surface font-semibold">{part}</strong> : part)}
              </span>
            </div>
          )
        }
        if (line.trim() === '') {
          return <div key={idx} className="h-2" />
        }
        return <p key={idx}>{line}</p>
      })}
    </div>
  )
}

const CaseReportsPage = () => {
  const { caseData, refreshCase } = useOutletContext<CaseContextType>()
  const [inventory, setInventory] = useState<CaseReportInventory | null>(null)
  const [generating, setGenerating] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selectedReport, setSelectedReport] = useState<CaseReportItem | null>(null)
  const [reportContent, setReportContent] = useState<string | null>(null)
  const [loadingContent, setLoadingContent] = useState(false)

  const loadReports = async () => {
    try {
      const data = await listCaseReports(caseData.id)
      setInventory(data)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load reports')
    }
  }

  useEffect(() => {
    let cancelled = false

    const refreshReports = async () => {
      try {
        const data = await listCaseReports(caseData.id)
        if (!cancelled) {
          setInventory(data)
          setError(null)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load reports')
        }
      }
    }

    refreshReports()
    const intervalId = window.setInterval(refreshReports, 15000)

    return () => {
      cancelled = true
      window.clearInterval(intervalId)
    }
  }, [caseData.id])

  const handleGenerate = async (reportType: 'executive' | 'technical' | 'timeline' | 'ioc') => {
    try {
      setError(null)
      setGenerating(reportType)
      const report = await generateCaseReport(caseData.id, reportType)
      await loadReports()
      await refreshCase()
      
      // Auto-select and preview the newly generated report
      handleSelectReport(report)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate report')
    } finally {
      setGenerating(null)
    }
  }

  const handleSelectReport = async (report: CaseReportItem) => {
    setSelectedReport(report)
    setReportContent(null)
    setLoadingContent(true)
    try {
      const data = await getCaseReportContent(caseData.id, report.name)
      setReportContent(data.content)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to read report content')
    } finally {
      setLoadingContent(false)
    }
  }

  const handleDownload = () => {
    if (!reportContent || !selectedReport) return
    const blob = new Blob([reportContent], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = selectedReport.name
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="fade-in space-y-8 max-w-7xl">
      {error && (
        <GlassPanel className="p-4 border-error/30 bg-error/5 animate-shake">
          <div className="flex items-center gap-2 text-error">
            <span className="material-symbols-outlined">error</span>
            <span className="font-mono text-label-sm">{error}</span>
          </div>
        </GlassPanel>
      )}

      {/* Report Types Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {reportTemplates.map(template => (
          <GlassPanel key={template.type} className="report-card flex flex-col justify-between h-full">
            <div>
              <div className="flex items-center gap-3 mb-3">
                <span className="material-symbols-outlined text-3xl text-secondary">
                  {template.icon}
                </span>
                <h3 className="font-title-md text-title-sm text-on-surface uppercase tracking-wider">
                  {template.title}
                </h3>
              </div>
              <p className="text-body-sm text-on-surface-variant/70 mb-4 line-clamp-3 leading-relaxed">
                {template.description}
              </p>
            </div>
            <button
              onClick={() => handleGenerate(template.type)}
              disabled={generating !== null}
              className="btn-secondary w-full py-2 flex items-center justify-center gap-2 disabled:opacity-50 font-label-sm text-label-sm"
            >
              <span className="material-symbols-outlined text-lg">
                {generating === template.type ? 'progress_activity' : 'add_circle'}
              </span>
              {generating === template.type ? 'GENERATING...' : 'GENERATE'}
            </button>
          </GlassPanel>
        ))}
      </div>

      {/* Main Reports Split Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-[350px_1fr] gap-6">
        
        {/* Left column: Inventory */}
        <GlassPanel className="overflow-hidden flex flex-col h-[600px]">
          <div className="h-12 border-b border-white/10 px-4 flex items-center justify-between bg-black/25 shrink-0">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-secondary">inventory_2</span>
              <span className="font-mono text-[11px] tracking-[0.15em] uppercase text-on-surface">
                REPORT INVENTORY
              </span>
            </div>
            <span className="font-mono text-[10px] text-on-surface-variant/60">
              {inventory?.count || 0} FILES
            </span>
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar divide-y divide-white/5 bg-black/10">
            {!inventory || inventory.reports.length === 0 ? (
              <div className="p-8 text-center mt-12">
                <span className="material-symbols-outlined text-4xl text-on-surface-variant/30 mb-3 block">
                  description
                </span>
                <p className="text-body-sm text-on-surface-variant/50">
                  No reports generated. Select a template above to generate a forensic report.
                </p>
              </div>
            ) : (
              inventory.reports.map(report => (
                <button
                  key={report.id}
                  onClick={() => handleSelectReport(report)}
                  className={`w-full text-left px-4 py-3.5 hover:bg-white/[0.02] transition-colors flex flex-col gap-1.5 ${
                    selectedReport?.id === report.id ? 'bg-secondary/10 border-l-2 border-secondary pl-3' : ''
                  }`}
                >
                  <div className="font-mono text-xs text-on-surface truncate w-full">
                    {report.name}
                  </div>
                  <div className="flex items-center justify-between w-full">
                    <span className="font-mono text-[9px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-white/5 text-on-surface-variant/70">
                      {report.report_type}
                    </span>
                    <span className="font-mono text-[9px] text-on-surface-variant/40">
                      {formatBytes(report.size)}
                    </span>
                  </div>
                </button>
              ))
            )}
          </div>
        </GlassPanel>

        {/* Right column: Report Previewer */}
        <GlassPanel className="overflow-hidden flex flex-col h-[600px]">
          <div className="h-12 border-b border-white/10 px-4 flex items-center justify-between bg-black/25 shrink-0">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-secondary">visibility</span>
              <span className="font-mono text-[11px] tracking-[0.15em] uppercase text-on-surface">
                REPORT LIVE PREVIEW
              </span>
            </div>
            {selectedReport && reportContent && (
              <button
                onClick={handleDownload}
                className="flex items-center gap-1.5 px-3 py-1 bg-secondary text-on-secondary font-label-sm text-xs rounded hover:opacity-90 transition-all font-semibold"
              >
                <span className="material-symbols-outlined text-sm">download</span>
                DOWNLOAD REPORT
              </button>
            )}
          </div>

          <div className="flex-1 p-6 overflow-y-auto custom-scrollbar bg-black/15">
            {loadingContent ? (
              <div className="flex flex-col items-center justify-center h-full gap-3">
                <span className="material-symbols-outlined text-4xl text-secondary animate-spin">
                  progress_activity
                </span>
                <span className="font-mono text-xs text-on-surface-variant/60">
                  DECRYPTING REPORT CONTENT...
                </span>
              </div>
            ) : selectedReport && reportContent ? (
              <div className="max-w-3xl mx-auto neural-scanline relative">
                <div className="mb-4 flex items-center justify-between text-xs font-mono border-b border-white/5 pb-3 text-on-surface-variant/40">
                  <span>PATH: {selectedReport.relative_path}</span>
                  <span>SHA256: {selectedReport.sha256?.slice(0, 10)}...</span>
                </div>
                <SimpleMarkdownRenderer text={reportContent} />
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-center p-8">
                <span className="material-symbols-outlined text-5xl text-on-surface-variant/20 mb-4">
                  quick_reference_all
                </span>
                <h3 className="font-title-md text-title-sm text-on-surface/80 mb-2 uppercase tracking-wide">
                  Select a Report
                </h3>
                <p className="text-body-sm text-on-surface-variant/50 max-w-md">
                  Select a generated report from the left inventory list to perform live visualization, analysis, or export the report as markdown.
                </p>
              </div>
            )}
          </div>
        </GlassPanel>
      </div>
    </div>
  )
}

export default CaseReportsPage
