import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getScan, ScanResponse } from '../services/api'
import GlassPanel from '../components/ui/GlassPanel'
import ThreatBadge from '../components/ui/ThreatBadge'

const AIBriefingPage = () => {
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
    return () => {
      mounted = false
    }
  }, [scanId])

  if (loading) {
    return (
      <div className="container-padding flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <span className="material-symbols-outlined text-6xl text-secondary animate-spin mb-4 block">
            progress_activity
          </span>
          <p className="font-title-md text-title-md text-on-surface">Loading briefing...</p>
        </div>
      </div>
    )
  }

  if (error || !scan) {
    return (
      <div className="container-padding">
        <GlassPanel className="p-12 text-center">
          <span className="material-symbols-outlined text-6xl text-error mb-4 block">error</span>
          <h2 className="font-title-md text-title-md text-on-surface mb-2">Briefing Not Available</h2>
          <p className="text-body-md text-on-surface-variant mb-6">{error}</p>
          <Link to="/" className="btn-secondary px-6 py-3 inline-flex items-center gap-2">
            <span className="material-symbols-outlined">arrow_back</span>
            Return to Upload
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

  return (
    <div className="container-padding fade-in">
      <section className="mb-16 relative max-w-4xl">
        <div className="flex items-center gap-2 mb-4">
          {risk && <ThreatBadge severity={risk.severity} label="Threat Briefing" />}
          <span className="text-on-surface-variant font-label-sm text-label-sm opacity-50">
            - EVIDENCE-BACKED INVESTIGATION REPORT
          </span>
        </div>
        <h1 className="font-display-xl text-display-xl tracking-tighter text-on-surface leading-tight mb-6">
          {scan.filename}
        </h1>
        <p className="font-body-lg text-body-lg text-on-surface-variant max-w-2xl leading-relaxed">
          {risk?.summary || 'No risk summary has been generated for this APK yet.'}
        </p>
      </section>

      <section className="mb-section-gap">
        <h2 className="font-title-md text-title-md text-on-surface mb-12 flex items-center gap-4">
          EXECUTIVE SUMMARY
          <div className="h-px bg-white/10 flex-grow"></div>
        </h2>

        <GlassPanel className="p-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div>
              <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-2">Severity</span>
              <span className="font-display-xl text-title-md text-on-surface">{risk?.severity || 'UNKNOWN'}</span>
            </div>
            <div>
              <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-2">Overall Risk</span>
              <span className="font-display-xl text-title-md text-on-surface">{risk?.risk_score || 0}/100</span>
            </div>
            <div>
              <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-2">Technical</span>
              <span className="font-display-xl text-title-md text-primary">{risk?.technical_risk_score ?? risk?.risk_score ?? 0}/100</span>
            </div>
            <div>
              <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-2">Fraud</span>
              <span className="font-display-xl text-title-md text-secondary">{risk?.fraud_risk_score ?? 0}/100</span>
            </div>
          </div>
        </GlassPanel>
      </section>

      <section className="mb-section-gap grid grid-cols-1 lg:grid-cols-2 gap-gutter">
        <GlassPanel className="p-8">
          <h2 className="font-title-md text-title-md text-on-surface mb-6">Threat Classification</h2>
          {classification ? (
            <div className="space-y-3">
              <p className="text-body-lg text-on-surface">{classification.threat_type}</p>
              <p className="text-body-md text-on-surface-variant">{classification.threat_family}</p>
              <p className="text-body-sm text-on-surface-variant">Confidence: {classification.confidence}%</p>
              {(classification.evidence || []).slice(0, 6).map((item: string, index: number) => (
                <p key={index} className="font-mono text-xs text-on-surface-variant">&gt; {item}</p>
              ))}
            </div>
          ) : (
            <p className="text-body-md text-on-surface-variant">No threat classification stored yet.</p>
          )}
        </GlassPanel>

        <GlassPanel className="p-8">
          <h2 className="font-title-md text-title-md text-on-surface mb-6">Fraud Intent</h2>
          {fraudIntent?.objectives?.length ? (
            <div className="space-y-4">
              {fraudIntent.objectives.map((objective: any, index: number) => (
                <div key={index}>
                  <p className="text-body-lg text-on-surface">{objective.objective}</p>
                  <p className="text-body-sm text-on-surface-variant">{objective.confidence}% confidence</p>
                  <p className="text-body-sm text-on-surface-variant mt-1">{objective.fraud_impact}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-body-md text-on-surface-variant">Insufficient evidence for a specific fraud objective.</p>
          )}
        </GlassPanel>
      </section>

      <section className="mb-section-gap">
        <h2 className="font-title-md text-title-md text-on-surface mb-12 flex items-center gap-4">
          TECHNICAL FINDINGS
          <div className="h-px bg-white/10 flex-grow"></div>
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-gutter">
          <GlassPanel className="p-6">
            <h3 className="font-title-md text-title-md text-on-surface mb-4">APK Evidence</h3>
            <div className="grid grid-cols-2 gap-3 text-body-md">
              <span className="text-on-surface-variant">Package</span><span className="text-on-surface font-mono truncate">{apk.package_name || 'N/A'}</span>
              <span className="text-on-surface-variant">Permissions</span><span className="text-on-surface">{apk.permissions?.length || 0}</span>
              <span className="text-on-surface-variant">Exported</span><span className="text-on-surface">{apk.exported_components?.length || 0}</span>
              <span className="text-on-surface-variant">Strings</span><span className="text-on-surface">{apk.string_count || apk.strings?.length || 0}</span>
              <span className="text-on-surface-variant">Certificates</span><span className="text-on-surface">{apk.certificates?.length || 0}</span>
              <span className="text-on-surface-variant">URLs/Domains</span><span className="text-on-surface">{(apk.urls?.length || 0) + (apk.domains?.length || 0)}</span>
            </div>
          </GlassPanel>

          <GlassPanel className="p-6">
            <h3 className="font-title-md text-title-md text-on-surface mb-4">Risk Contributors</h3>
            {risk?.contributors?.length ? (
              <div className="space-y-2">
                {risk.contributors.slice(0, 8).map((item: any, index: number) => (
                  <div key={index} className="flex items-center justify-between">
                    <span className="text-body-md text-on-surface-variant">{item.label}</span>
                    <span className="font-mono text-secondary">{item.score}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-body-md text-on-surface-variant">No scored contributors stored yet.</p>
            )}
          </GlassPanel>
        </div>
      </section>

      <section className="mb-section-gap">
        <h2 className="font-title-md text-title-md text-on-surface mb-12 flex items-center gap-4">
          ATTACK FLOW
          <div className="h-px bg-white/10 flex-grow"></div>
        </h2>
        {attackFlow?.steps?.length ? (
          <div className="space-y-4">
            {attackFlow.steps.map((step: any) => (
              <GlassPanel key={step.order} className="p-6">
                <p className="font-title-md text-title-md text-on-surface">{step.order}. {step.title}</p>
                <p className="text-body-sm text-on-surface-variant mb-3">{step.stage} / {step.confidence}% confidence</p>
                {(step.evidence || []).slice(0, 5).map((item: string, index: number) => (
                  <p key={index} className="font-mono text-xs text-on-surface-variant">&gt; {item}</p>
                ))}
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
          RECOMMENDATIONS
          <div className="h-px bg-white/10 flex-grow"></div>
        </h2>
        {recommendations.length ? (
          <div className="space-y-4">
            {recommendations.map((rec: any, index: number) => (
              <GlassPanel key={index} className="p-6">
                <p className="text-body-lg text-on-surface">{rec.action}</p>
                <p className="text-body-sm text-on-surface-variant uppercase mt-1">{rec.priority || 'info'}</p>
              </GlassPanel>
            ))}
          </div>
        ) : (
          <GlassPanel className="p-8">
            <p className="text-body-md text-on-surface-variant">No recommendations stored yet.</p>
          </GlassPanel>
        )}
      </section>

      <section>
        <div className="flex gap-4 justify-center">
          <Link to={`/scan/${scanId}`} className="btn-secondary px-8 py-3 font-label-sm text-label-sm">
            <span className="material-symbols-outlined text-sm">arrow_back</span>
            BACK TO ANALYSIS
          </Link>
          <button onClick={() => window.print()} className="btn-secondary px-8 py-3 font-label-sm text-label-sm">
            <span className="material-symbols-outlined text-sm">print</span>
            EXPORT REPORT
          </button>
        </div>
      </section>
    </div>
  )
}

export default AIBriefingPage
