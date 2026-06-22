import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useNeuralLab } from '../hooks/useNeuralLab'
import GlassPanel from '../components/ui/GlassPanel'
import ThreatBadge from '../components/ui/ThreatBadge'
import { RecentInvestigation, neuralApi } from '../services/neuralApi'
import { ThreatIngestionWizard } from '../components/neural-lab/ThreatIngestionWizard'
import NeuralCommandBar from '../components/neural-lab/NeuralCommandBar'
import AnalysisPipeline from '../components/neural-lab/AnalysisPipeline'
import ThreatOverview from '../components/neural-lab/ThreatOverview'
import AICognitionConsole from '../components/neural-lab/AICognitionConsole'
import SuspiciousAPIPanel from '../components/neural-lab/SuspiciousAPIPanel'
import BehaviorMatrix from '../components/neural-lab/BehaviorMatrix'
import IOCTable from '../components/neural-lab/IOCTable'
import ThreatGraph from '../components/neural-lab/ThreatGraph'
import SandboxTimeline from '../components/neural-lab/SandboxTimeline'
import AIChatInvestigator from '../components/neural-lab/AIChatInvestigator'
import InvestigationSidebar from '../components/neural-lab/InvestigationSidebar'
import ActivityFeed from '../components/neural-lab/ActivityFeed'
import ReportPanel from '../components/neural-lab/ReportPanel'
import NeuralWorkstation from '../components/neural-lab/NeuralWorkstation'
import EvidenceNavigator from '../components/neural-lab/EvidenceNavigator'

type NeuralTab =
  | 'overview'
  | 'functions'
  | 'behavior'
  | 'ioc'
  | 'graph'
  | 'sandbox'
  | 'chat'
  | 'reports'

const TAB_CONFIG: { id: NeuralTab; label: string; icon: string }[] = [
  { id: 'overview', label: 'THREAT OVERVIEW', icon: 'dashboard' },
  { id: 'functions', label: 'SUSPICIOUS APIS', icon: 'code' },
  { id: 'behavior', label: 'BEHAVIOR MATRIX', icon: 'grid_view' },
  { id: 'ioc', label: 'IOC TABLE', icon: 'share' },
  { id: 'graph', label: 'CALL GRAPH', icon: 'hub' },
  { id: 'sandbox', label: 'PREDICTED BEHAVIOR', icon: 'psychology' },
  { id: 'chat', label: 'AI CHAT', icon: 'chat' },
  { id: 'reports', label: 'REPORTS', icon: 'description' },
]

const NeuralLabPage = () => {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<NeuralTab>('overview')
  const [wizardOpen, setWizardOpen] = useState(false)
  const [recentInvestigations, setRecentInvestigations] = useState<RecentInvestigation[]>([])

  useEffect(() => {
    const handleSelectFunction = (e: any) => {
      const { signature } = e.detail
      setActiveTab('functions')
      setTimeout(() => {
        window.dispatchEvent(new CustomEvent('sentinel:internal-select-function', { 
          detail: { signature } 
        }))
      }, 50)
    }

    window.addEventListener('sentinel:select-function', handleSelectFunction)
    return () => window.removeEventListener('sentinel:select-function', handleSelectFunction)
  }, [])

  useEffect(() => {
    if (!scanId) {
      neuralApi.getRecentInvestigations()
        .then((res) => setRecentInvestigations(res))
        .catch((err) => console.error('Failed to load recent investigations', err))
    }
  }, [scanId])

  if (!scanId) {
    return (
      <div className="container-padding fade-in sentinel-mono">
        <section className="mb-12 relative max-w-6xl">
          <div className="flex items-center gap-2 mb-4">
            <ThreatBadge severity="MEDIUM" label="Neural Lab Standby" />
            <span className="text-on-surface-variant font-label-sm text-label-sm opacity-50">
              REVERSE ENGINEERING PIPELINE
            </span>
          </div>
          <div className="mono-oath p-6">
            <h1 className="font-display-xl text-display-xl tracking-tighter text-on-surface leading-tight mb-4">
              NEURAL LAB
            </h1>
            <p className="font-body-lg text-body-lg text-on-surface-variant max-w-3xl leading-relaxed">
              AI-assisted malware investigation environment for APK reverse engineering, Ghidra analysis,
              behavior mapping, and forensic cognition.
            </p>
          </div>
        </section>

        {recentInvestigations.length > 0 && (
          <section className="mb-12 max-w-6xl">
            <div className="flex items-center justify-between mb-6">
              <h2 className="font-title-md text-title-md text-on-surface flex items-center gap-2">
                <span className="material-symbols-outlined text-secondary">history</span>
                RESUME ACTIVE SESSIONS
              </h2>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-gutter">
              {recentInvestigations.map((inv) => (
                <div
                  key={inv.id}
                  onClick={() => navigate(`/neural-lab/${inv.scan_id}`)}
                  className="glass-panel p-6 rounded-xl border border-outline-variant/30 hover:border-secondary/40 hover:scale-[1.01] transition-all cursor-pointer flex flex-col justify-between group relative overflow-hidden"
                >
                  <div className="flex justify-between items-start gap-4 mb-4">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1.5">
                        <span className="font-mono text-label-sm text-secondary uppercase tracking-wider">
                          {inv.title || 'Untitled Session'}
                        </span>
                        <span className="text-on-surface-variant/30">/</span>
                        <span className="text-body-sm text-on-surface-variant">
                          {new Date(inv.created_at).toLocaleDateString()}
                        </span>
                      </div>
                      <h3 className="font-title-md text-title-md text-on-surface truncate group-hover:text-secondary transition-colors font-semibold">
                        {inv.app_name}
                      </h3>
                      <p className="font-mono text-body-sm text-on-surface-variant/50 truncate mt-1">
                        File: {inv.filename}
                      </p>
                    </div>
                    {inv.risk_score !== undefined && (
                      <div className="text-right">
                        <div className="text-display-xs font-display-xs text-secondary font-mono leading-none">
                          {Math.round(inv.risk_score)}
                        </div>
                        <div className="text-label-sm text-on-surface-variant opacity-70">RISK INDEX</div>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center justify-between border-t border-outline-variant/10 pt-4 mt-2">
                    <span className="text-body-sm text-on-surface-variant flex items-center gap-1">
                      <span className="material-symbols-outlined text-sm">person</span>
                      {inv.analyst_name || 'Analyst'}
                    </span>
                    <span className="text-secondary font-label-sm text-label-sm flex items-center gap-1 group-hover:translate-x-1 transition-transform">
                      Resume Investigation
                      <span className="material-symbols-outlined text-sm">arrow_forward</span>
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        <section className="mb-section-gap max-w-6xl">
          <GlassPanel className="mono-panel p-12 text-center">
            <span className="material-symbols-outlined text-6xl text-secondary mb-6 block">
              neurology
            </span>
            <h2 className="font-title-md text-title-md text-on-surface mb-4">
              No Investigation Active
            </h2>
            <p className="text-body-md text-on-surface-variant mb-8 max-w-2xl mx-auto">
              Upload an APK and run analysis to enter the workstation.
            </p>
            <button onClick={() => setWizardOpen(true)} className="btn-primary inline-flex px-8 py-3 w-auto mx-auto">
              <span className="material-symbols-outlined">upload</span>
              INITIATE THREAT INGESTION
            </button>
          </GlassPanel>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-gutter mt-12">
            {[
              { icon: 'code', title: 'JADX Decompilation', desc: 'Java source extraction from DEX bytecode' },
              { icon: 'memory', title: 'Ghidra Analysis', desc: 'Native and bytecode reverse engineering' },
              { icon: 'hub', title: 'Call Graph Analysis', desc: 'Function relationship and flow mapping' },
              { icon: 'psychology', title: 'AI Cognition', desc: 'Explainable threat intelligence support' },
            ].map((card) => (
              <GlassPanel key={card.title} className="mono-panel p-6">
                <span className="material-symbols-outlined text-3xl text-secondary mb-4 block">{card.icon}</span>
                <h3 className="font-title-md text-title-md mb-2 text-on-surface">{card.title}</h3>
                <p className="text-body-md text-on-surface-variant">{card.desc}</p>
              </GlassPanel>
            ))}
          </div>
        </section>

        <ThreatIngestionWizard isOpen={wizardOpen} onClose={() => setWizardOpen(false)} />
      </div>
    )
  }

  return <NeuralLabActive scanId={scanId} activeTab={activeTab} setActiveTab={setActiveTab} />
}

interface NeuralLabActiveProps {
  scanId: string
  activeTab: NeuralTab
  setActiveTab: (tab: NeuralTab) => void
}

const NeuralLabActive = ({ scanId, activeTab, setActiveTab }: NeuralLabActiveProps) => {
  const lab = useNeuralLab(scanId)
  const neural = lab.scan?.analysis_result?.neural_analysis
  const rankedFunctions = lab.scan?.analysis_result?.top_suspicious_functions ?? []
  const suspiciousFunctions = (neural?.suspicious_functions?.length ? neural.suspicious_functions : rankedFunctions.map((item: any) => ({
    name: item.function_name?.split('.').pop() || item.function_name,
    class_name: item.function_name?.split('.').slice(0, -1).join('.') || 'unknown',
    signature: item.function_name,
    threat_indicators: [item.reason].filter(Boolean),
    decompiled_code: item.decompiled_code || undefined,
    risk_score: item.risk_score,
    call_count: 0,
    called_by: [],
    calls_to: [],
  }))) ?? []
  const malwareIndicators = neural?.malware_indicators ?? []
  const behavioralPatterns = neural?.behavioral_patterns ?? []
  const callGraph = neural?.call_graph ?? {}
  const permissions = (lab.scan?.analysis_result?.permissions ?? []).map((permission) => permission.name)
  const yaraMatches = neural?.yara_scan?.matches ?? []
  const aiHealthy = lab.healthStatus?.ollama_running ?? false

  const handleTabChange = (tabId: NeuralTab) => {
    setActiveTab(tabId)
    // Add visual feedback or logic for guided flow
    if (tabId === 'functions') {
      lab.addNote('Started deep function analysis.', 'activity', ['workflow'])
    }
  }

  if (lab.loading) {
    return (
      <div className="container-padding flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <div className="relative mb-6">
            <span className="material-symbols-outlined text-6xl text-secondary">neurology</span>
            <div className="absolute inset-0 border-2 border-secondary/30 rounded-full animate-ping" />
          </div>
          <p className="font-title-md text-title-md text-on-surface mb-2">Loading Neural Lab</p>
          <p className="font-label-sm text-label-sm text-on-surface-variant font-mono">
            [ Initializing Reverse Engineering Pipeline ]
          </p>
        </div>
      </div>
    )
  }

  if (!lab.scan) {
    return (
      <div className="container-padding">
        <GlassPanel className="p-12 text-center">
          <span className="material-symbols-outlined text-6xl text-error mb-4 block">error</span>
          <h2 className="font-title-md text-title-md text-on-surface mb-2">Analysis Not Found</h2>
          <Link to="/" className="btn-secondary px-6 py-3 inline-flex items-center gap-2 mt-4">
            <span className="material-symbols-outlined">arrow_back</span>
            Return to Ingestion
          </Link>
        </GlassPanel>
      </div>
    )
  }

  return (
    <div className="container-padding fade-in select-none sentinel-mono">
      <section className="mb-8 max-w-full">
        <div className="flex items-center gap-2 mb-3">
          <ThreatBadge severity="HIGH" label="Neural Lab Active" />
          <span className="text-on-surface-variant font-label-sm text-label-sm opacity-50">
            {lab.scan.analysis_result?.app_name || lab.scan.filename}
          </span>
        </div>
        <h1 className="font-display-xl text-display-xl tracking-tighter text-on-surface leading-tight mb-2">
          NEURAL LAB
        </h1>
      </section>

      <NeuralWorkstation
        commandBar={
          <NeuralCommandBar
            appName={lab.scan.analysis_result?.app_name || lab.scan.filename || 'Unknown APK'}
            packageName={lab.scan.analysis_result?.package_name || 'unknown.package'}
            versionName={lab.scan.analysis_result?.version_name || '1.0.0'}
            riskScore={lab.riskData?.banking_intelligence?.overall_risk ?? lab.scan.analysis_result?.risk_assessment?.risk_score ?? 0}
            severity={lab.riskData?.banking_intelligence?.threat_classification ?? lab.scan.analysis_result?.risk_assessment?.severity ?? 'LOW'}
            pipelineRunning={lab.pipelineRunning}
            pipelineProgress={lab.pipelineProgress}
            investigations={lab.investigations}
            activeInvestigation={lab.activeInvestigation}
            onSwitchInvestigation={lab.switchInvestigation}
            onCreateInvestigation={() => lab.createInvestigation('New Investigation', 'Forensic session', 'Analyst')}
            onRunAnalysis={lab.runAnalysisPipeline}
            onOpenReport={() => setActiveTab('reports')}
            aiHealthy={aiHealthy}
          />
        }
        activity={
          <div className="space-y-4">
            {lab.pipelineRunning && (
              <AnalysisPipeline
                stages={lab.pipelineStages}
                pipelineRunning={lab.pipelineRunning}
              />
            )}
            <ActivityFeed />
          </div>
        }
        tabs={
          <div className="flex gap-1 flex-wrap bg-surface-variant/10 p-1 rounded-lg border border-white/5">
            {TAB_CONFIG.map((tab) => (
              <button
                key={tab.id}
                onClick={() => handleTabChange(tab.id)}
                className={`px-4 py-2 rounded-md font-label-sm text-label-sm transition-all flex items-center gap-1.5 ${
                  activeTab === tab.id
                    ? 'bg-secondary text-on-secondary shadow-lg shadow-secondary/20'
                    : 'hover:bg-white/5 text-on-surface-variant'
                }`}
              >
                <span className="material-symbols-outlined text-sm">{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </div>
        }
        navigator={
          <EvidenceNavigator
            scan={lab.scan}
            suspiciousFunctions={suspiciousFunctions}
            malwareIndicators={malwareIndicators}
            behavioralPatterns={behavioralPatterns}
            permissions={permissions}
            aiHealthy={aiHealthy}
          />
        }
        sidebar={
          <InvestigationSidebar
            investigations={lab.investigations}
            activeInvestigation={lab.activeInvestigation}
            notes={lab.notes}
            bookmarks={lab.bookmarks}
            onSwitch={lab.switchInvestigation}
            onCreate={lab.createInvestigation}
            onAddNote={lab.addNote}
          />
        }
      >
        <div className="space-y-8">
          {activeTab === 'overview' && (
            <>
              <ThreatOverview
                riskData={lab.riskData}
                totalFunctions={suspiciousFunctions.length}
                totalIndicators={malwareIndicators.length}
                totalPatterns={behavioralPatterns.length}
              />
              <AICognitionConsole
                summary={lab.aiSummary}
                riskData={lab.riskData}
                aiHealthy={aiHealthy}
              />
            </>
          )}

          {activeTab === 'functions' && (
            <SuspiciousAPIPanel
              scanId={scanId}
              functions={suspiciousFunctions}
              activeInvestigationId={lab.activeInvestigation?.id}
              onAddBookmark={lab.addBookmark}
            />
          )}

          {activeTab === 'behavior' && (
            <BehaviorMatrix
              patterns={behavioralPatterns}
              yaraMatches={yaraMatches}
            />
          )}

          {activeTab === 'ioc' && (
            <IOCTable indicators={malwareIndicators} />
          )}

          {activeTab === 'graph' && (
            <ThreatGraph
              callGraph={callGraph}
              suspiciousFunctions={suspiciousFunctions}
            />
          )}

          {activeTab === 'sandbox' && (
            <SandboxTimeline sandboxData={lab.sandboxData} />
          )}

          {activeTab === 'chat' && (
            <AIChatInvestigator
              messages={lab.chatMessages}
              chatLoading={lab.chatLoading}
              onSendMessage={lab.sendChatMessage}
              onClearHistory={lab.clearChatHistory}
            />
          )}

          {activeTab === 'reports' && (
            <ReportPanel scanId={scanId} />
          )}
        </div>
      </NeuralWorkstation>
    </div>
  )
}

export default NeuralLabPage
