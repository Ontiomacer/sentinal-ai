import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getScan, ScanResponse } from '../services/api'
import GlassPanel from '../components/ui/GlassPanel'
import ThreatBadge from '../components/ui/ThreatBadge'
import NeuralTerminal from '../components/ui/NeuralTerminal'
import IntelligenceFeed from '../components/ui/IntelligenceFeed'

const severityColor = (severity?: string) => {
  switch (severity) {
    case 'CRITICAL': return 'text-error'
    case 'HIGH': return 'text-secondary'
    case 'MEDIUM': return 'text-primary'
    default: return 'text-tertiary'
  }
}

const ScanAnalysisPage = () => {
  const { scanId } = useParams<{ scanId: string }>()
  const [scan, setScan] = useState<ScanResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let mounted = true
    const fetchScan = async () => {
      if (!scanId) return
      try {
        const data = await getScan(scanId)
        if (mounted) setScan(data)
      } catch (err: any) {
        if (mounted) setError(err.response?.data?.detail || 'Failed to load scan results')
      } finally {
        if (mounted) setLoading(false)
      }
    }

    fetchScan()
    const interval = setInterval(() => {
      if (scan?.status === 'analyzing') void fetchScan()
    }, 3000)

    return () => {
      mounted = false
      clearInterval(interval)
    }
  }, [scanId, scan?.status])

  if (loading) {
    return (
      <div className="container-padding flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <span className="material-symbols-outlined text-6xl text-secondary animate-spin mb-4 block">
            progress_activity
          </span>
          <p className="font-title-md text-title-md text-on-surface">Loading analysis artifacts...</p>
        </div>
      </div>
    )
  }

  if (error || !scan) {
    return (
      <div className="container-padding">
        <GlassPanel className="p-12 text-center">
          <span className="material-symbols-outlined text-6xl text-error mb-4 block">error</span>
          <h2 className="font-title-md text-title-md text-on-surface mb-2">Investigation Failed</h2>
          <p className="text-body-md text-on-surface-variant mb-6">{error}</p>
          <Link to="/" className="btn-secondary px-6 py-3 inline-flex items-center gap-2">
            <span className="material-symbols-outlined">arrow_back</span>
            Return to Ingestion
          </Link>
        </GlassPanel>
      </div>
    )
  }

  const analysis = scan.analysis_result || {}
  const apk = analysis.apk_analysis || analysis
  const risk = analysis.risk_assessment || analysis.threat_assessment
  const classification = analysis.threat_classification
  const fraudIntent = analysis.fraud_intent
  const attackFlow = analysis.attack_flow
  const recommendations = analysis.recommendations || []

  const terminalLogs = [
    { timestamp: '', type: 'success' as const, message: 'LOADED STORED APK ANALYSIS' },
    { timestamp: '', type: 'info' as const, message: `> File: ${scan.filename}` },
    { timestamp: '', type: 'info' as const, message: `> SHA256: ${scan.sha256.substring(0, 16)}...` },
    { timestamp: '', type: 'warning' as const, message: `PACKAGE: ${apk.package_name || 'Unknown'}` },
    { timestamp: '', type: 'info' as const, message: `> Permissions: ${apk.permissions?.length || 0}` },
    { timestamp: '', type: 'info' as const, message: `> Exported components: ${apk.exported_components?.length || 0}` },
    ...(risk ? [{
      timestamp: '',
      type: risk.severity === 'CRITICAL' || risk.severity === 'HIGH' ? 'error' as const : 'success' as const,
      message: `RISK: ${risk.severity} (${risk.risk_score}/100)`,
    }] : []),
  ]

  const feedItems = [
    ...(classification ? [{
      timestamp: 'CLASSIFICATION',
      message: `${classification.threat_family} (${classification.confidence}% confidence)`,
      severity: 'primary' as const,
    }] : []),
    ...(fraudIntent?.objectives || []).slice(0, 2).map((objective: any) => ({
      timestamp: 'FRAUD',
      message: `${objective.objective} (${objective.confidence}% confidence)`,
      severity: 'secondary' as const,
    })),
    ...recommendations.slice(0, 2).map((rec: any) => ({
      timestamp: String(rec.priority || 'INFO').toUpperCase(),
      message: rec.action,
      severity: 'tertiary' as const,
    })),
  ]

  return (
    <div className="container-padding fade-in">
      <section className="mb-16 relative max-w-4xl">
        <div className="flex items-center gap-2 mb-4">
          {risk && (
            <ThreatBadge severity={risk.severity} label={`${risk.severity} (${risk.risk_score}/100)`} />
          )}
          <span className="text-on-surface-variant font-label-sm text-label-sm opacity-50">
            - INVESTIGATION ID: {scanId?.substring(0, 8).toUpperCase()}
          </span>
        </div>
        <h1 className="font-display-xl text-display-xl tracking-tighter text-on-surface leading-tight mb-6">
          {scan.filename}
        </h1>
        <p className="font-body-lg text-body-lg text-on-surface-variant max-w-2xl leading-relaxed">
          {risk?.summary || 'Analysis result is available, but no risk assessment has been generated yet.'}
        </p>
      </section>

      <section className="mb-section-gap grid grid-cols-12 gap-gutter items-start">
        <div className="col-span-12 lg:col-span-8 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-gutter">
            <GlassPanel className="p-6">
              <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-2">
                Overall Risk
              </span>
              <span className={`font-display-xl text-title-md ${severityColor(risk?.severity)}`}>
                {risk?.risk_score ?? 0}/100
              </span>
            </GlassPanel>
            <GlassPanel className="p-6">
              <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-2">
                Technical Risk
              </span>
              <span className="font-display-xl text-title-md text-on-surface">
                {risk?.technical_risk_score ?? risk?.risk_score ?? 0}/100
              </span>
            </GlassPanel>
            <GlassPanel className="p-6">
              <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-2">
                Fraud Risk
              </span>
              <span className="font-display-xl text-title-md text-secondary">
                {risk?.fraud_risk_score ?? 0}/100
              </span>
            </GlassPanel>
          </div>

          <GlassPanel className="p-8">
            <h2 className="font-title-md text-title-md mb-6 text-on-surface">Threat Classification</h2>
            {classification ? (
              <div className="space-y-3">
                <p className="text-body-lg text-on-surface">
                  {classification.threat_type} / {classification.threat_family}
                </p>
                <p className="text-body-sm text-on-surface-variant">Confidence: {classification.confidence}%</p>
                {(classification.evidence || []).slice(0, 8).map((item: string, index: number) => (
                  <p key={index} className="font-mono text-xs text-on-surface-variant">&gt; {item}</p>
                ))}
              </div>
            ) : (
              <p className="text-body-md text-on-surface-variant">No threat classification stored yet.</p>
            )}
          </GlassPanel>

          <GlassPanel className="p-8">
            <h2 className="font-title-md text-title-md mb-6 text-on-surface">Fraud Intent</h2>
            {fraudIntent?.objectives?.length ? (
              <div className="space-y-3">
                {fraudIntent.objectives.map((objective: any, index: number) => (
                  <div key={index} className="border border-white/10 rounded p-4 bg-white/[0.02]">
                    <div className="flex items-center justify-between gap-4 mb-2">
                      <p className="text-body-lg text-on-surface">{objective.objective}</p>
                      <span className="font-mono text-secondary">{objective.confidence}%</span>
                    </div>
                    <p className="text-body-sm text-on-surface-variant mb-2">{objective.fraud_impact}</p>
                    {(objective.evidence || []).slice(0, 4).map((item: string, evidenceIndex: number) => (
                      <p key={evidenceIndex} className="font-mono text-xs text-on-surface-variant/80">&gt; {item}</p>
                    ))}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-body-md text-on-surface-variant">Insufficient evidence for a specific fraud objective.</p>
            )}
          </GlassPanel>

          <GlassPanel className="p-8">
            <h2 className="font-title-md text-title-md mb-6 text-on-surface">Risk Contributors</h2>
            {risk?.contributors?.length ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {risk.contributors.slice(0, 10).map((item: any, index: number) => (
                  <div key={index} className="flex items-center justify-between p-3 glass-panel rounded">
                    <span className="text-body-md text-on-surface">{item.label}</span>
                    <span className="font-mono text-secondary">{item.score}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-body-md text-on-surface-variant">No scored contributors stored yet.</p>
            )}
          </GlassPanel>
        </div>

        <div className="col-span-12 lg:col-span-4 flex flex-col gap-gutter">
          <NeuralTerminal logs={terminalLogs} />
          <div className="flex gap-4">
            <Link to={`/briefing/${scanId}`} className="btn-primary flex-1">
              <span className="material-symbols-outlined text-sm">description</span>
              VIEW BRIEFING
            </Link>
          </div>
          <div className="flex gap-4">
            <Link to={`/neural-lab/${scanId}`} className="btn-secondary flex-1 px-4 py-3 flex items-center justify-center gap-2">
              <span className="material-symbols-outlined text-sm">neurology</span>
              NEURAL LAB
            </Link>
          </div>
          {feedItems.length > 0 && <IntelligenceFeed items={feedItems} />}
        </div>
      </section>

      <section className="mb-section-gap">
        <h2 className="font-title-md text-title-md text-on-surface mb-12 flex items-center gap-4">
          ATTACK FLOW RECONSTRUCTION
          <div className="h-px bg-white/10 flex-grow"></div>
        </h2>
        {attackFlow?.steps?.length ? (
          <div className="space-y-4">
            {attackFlow.steps.map((step: any) => (
              <GlassPanel key={step.order} className="p-6">
                <div className="flex items-start gap-4">
                  <span className="font-display-xl text-title-md text-secondary">{step.order}</span>
                  <div className="flex-1">
                    <h3 className="font-title-md text-title-md text-on-surface mb-1">{step.title}</h3>
                    <p className="text-body-sm text-on-surface-variant mb-3">
                      {step.stage} / {step.confidence}% confidence
                    </p>
                    {(step.evidence || []).slice(0, 6).map((item: string, index: number) => (
                      <p key={index} className="font-mono text-xs text-on-surface-variant">&gt; {item}</p>
                    ))}
                  </div>
                </div>
              </GlassPanel>
            ))}
          </div>
        ) : (
          <GlassPanel className="p-8">
            <p className="text-body-md text-on-surface-variant">Insufficient evidence to reconstruct an attack flow.</p>
          </GlassPanel>
        )}
      </section>

      <section className="mb-section-gap">
        <h2 className="font-title-md text-title-md text-on-surface mb-12 flex items-center gap-4">
          STATIC APK FINDINGS
          <div className="h-px bg-white/10 flex-grow"></div>
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-gutter">
          <GlassPanel className="p-6">
            <h3 className="font-label-sm text-label-sm text-on-surface-variant uppercase mb-4">Manifest</h3>
            <div className="space-y-3">
              <div>
                <span className="text-on-surface-variant text-label-sm font-label-sm block">Package</span>
                <span className="text-on-surface font-mono text-body-md">{apk.package_name || 'N/A'}</span>
              </div>
              <div>
                <span className="text-on-surface-variant text-label-sm font-label-sm block">Main Activity</span>
                <span className="text-on-surface font-mono text-body-md">{apk.main_activity || 'N/A'}</span>
              </div>
              <div>
                <span className="text-on-surface-variant text-label-sm font-label-sm block">SDK</span>
                <span className="text-on-surface text-body-md">
                  Min {apk.min_sdk_version || 'N/A'} / Target {apk.target_sdk_version || 'N/A'}
                </span>
              </div>
            </div>
          </GlassPanel>

          <GlassPanel className="p-6">
            <h3 className="font-label-sm text-label-sm text-on-surface-variant uppercase mb-4">Evidence Counts</h3>
            <div className="grid grid-cols-2 gap-3 text-body-md">
              <span className="text-on-surface-variant">Permissions</span><span className="text-on-surface">{apk.permissions?.length || 0}</span>
              <span className="text-on-surface-variant">Activities</span><span className="text-on-surface">{apk.activities?.length || 0}</span>
              <span className="text-on-surface-variant">Services</span><span className="text-on-surface">{apk.services?.length || 0}</span>
              <span className="text-on-surface-variant">Receivers</span><span className="text-on-surface">{apk.receivers?.length || 0}</span>
              <span className="text-on-surface-variant">Exported</span><span className="text-on-surface">{apk.exported_components?.length || 0}</span>
              <span className="text-on-surface-variant">Strings</span><span className="text-on-surface">{apk.string_count || apk.strings?.length || 0}</span>
              <span className="text-on-surface-variant">Certificates</span><span className="text-on-surface">{apk.certificates?.length || 0}</span>
              <span className="text-on-surface-variant">URLs/Domains</span><span className="text-on-surface">{(apk.urls?.length || 0) + (apk.domains?.length || 0)}</span>
            </div>
          </GlassPanel>
        </div>
      </section>

      <section className="mb-section-gap">
        <h2 className="font-title-md text-title-md text-on-surface mb-12 flex items-center gap-4">
          RECOMMENDATIONS
          <div className="h-px bg-white/10 flex-grow"></div>
        </h2>
        {recommendations.length ? (
          <div className="space-y-4">
            {recommendations.map((rec: any, index: number) => (
              <GlassPanel key={index} className="p-6">
                <div className="flex items-start gap-4">
                  <span className="material-symbols-outlined text-secondary">task_alt</span>
                  <div>
                    <p className="text-body-lg text-on-surface">{rec.action}</p>
                    <p className="text-body-sm text-on-surface-variant uppercase mt-1">{rec.priority || 'info'}</p>
                  </div>
                </div>
              </GlassPanel>
            ))}
          </div>
        ) : (
          <GlassPanel className="p-8">
            <p className="text-body-md text-on-surface-variant">No recommendations stored yet.</p>
          </GlassPanel>
        )}
      </section>
    </div>
  )
}

export default ScanAnalysisPage
