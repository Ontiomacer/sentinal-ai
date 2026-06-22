import React from 'react'
import GlassPanel from '../ui/GlassPanel'
import { RiskAssessmentResponse } from '../../services/neuralApi'

interface AICognitionConsoleProps {
  summary: string
  riskData: RiskAssessmentResponse | null
  aiHealthy: boolean
}

export const AICognitionConsole: React.FC<AICognitionConsoleProps> = ({
  riskData,
  aiHealthy,
}) => {
  const intel = riskData?.banking_intelligence
  const fraudScores = intel?.fraud_scores ?? {
    overall_risk: 0,
    credential_theft: 0,
    otp_theft: 0,
    upi_fraud: 0,
    account_takeover: 0,
    financial_data_exposure: 0,
  }

  const riskFactors = intel?.risk_factors ?? []
  const targetedApps = intel?.targeted_banking_apps ?? []
  const topFunctions = intel?.top_suspicious_functions ?? []

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs select-none">
      
      {/* AI Banking Fraud Intelligence Briefing */}
      <GlassPanel className="p-6 col-span-1 lg:col-span-2 border-border bg-surface-variant/15 flex flex-col">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-xs font-semibold text-primary tracking-wider uppercase flex items-center gap-1.5">
            <span className="material-symbols-outlined text-sm">analytics</span>
            BANKING FRAUD INTELLIGENCE BRIEFING
          </h4>
          <div className="flex items-center gap-2">
            {targetedApps.map((app) => (
              <span key={app} className="px-2 py-0.5 rounded bg-primary/20 text-primary border border-primary/30 text-[9px] uppercase font-bold">
                {app}
              </span>
            ))}
          </div>
        </div>
        
        <div className="flex-1 text-on-surface-variant leading-relaxed overflow-y-auto max-h-[400px] pr-2 font-mono whitespace-pre-wrap">
          {intel?.executive_summary ? (
            <div className="space-y-4">
              <div className="p-3 bg-primary/5 border-l-2 border-primary italic opacity-90 text-[11px]">
                {intel.executive_summary}
              </div>
              
              <div className="grid grid-cols-3 gap-4 mt-4">
                <div className="space-y-2">
                  <h5 className="text-[10px] font-bold text-secondary uppercase tracking-tighter">Fraud Intent</h5>
                  <p className="text-[11px] opacity-80">{intel.fraud_intent}</p>
                </div>
                <div className="space-y-2">
                  <h5 className="text-[10px] font-bold text-secondary uppercase tracking-tighter">Threat Classification</h5>
                  <p className="text-[11px] opacity-80">{intel.threat_classification}</p>
                </div>
                <div className="space-y-2">
                  <h5 className="text-[10px] font-bold text-secondary uppercase tracking-tighter">Confidence</h5>
                  <p className="text-[11px] opacity-80">{intel.confidence_score}%</p>
                </div>
              </div>

              <div className="mt-4">
                <h5 className="text-[10px] font-bold text-primary uppercase mb-2">Key Risk Contributors</h5>
                <div className="grid grid-cols-2 gap-2">
                  {riskFactors.slice(0, 6).map((factor, i) => (
                    <div key={i} className="flex items-center gap-2 p-2 rounded bg-surface border border-border/40">
                      <span className="material-symbols-outlined text-error text-[12px]">warning</span>
                      <span className="text-[10px] opacity-90">{factor}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-4">
                <h5 className="text-[10px] font-bold text-primary uppercase mb-2">Top Suspicious Functions</h5>
                <div className="space-y-2">
                  {topFunctions.map((func, i) => (
                    <div 
                      key={i} 
                      className="flex items-center justify-between p-2 rounded bg-surface/40 border border-border/20 hover:border-primary/30 transition-colors group cursor-pointer"
                      onClick={() => {
                        // Custom event to trigger explanation in CodeAnalysis tab or chat
                        window.dispatchEvent(new CustomEvent('explain-function', { detail: func.function_name }));
                      }}
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-[10px] text-on-surface-variant/50">#{i + 1}</span>
                        <div>
                          <div className="text-[11px] font-bold text-on-surface group-hover:text-primary transition-colors">
                            {func.function_name}
                          </div>
                          <div className="text-[9px] opacity-60 italic">{func.reason}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className="text-[10px] font-bold text-primary">+{func.risk_score}</div>
                        <span className="material-symbols-outlined text-sm opacity-0 group-hover:opacity-100 transition-opacity">psychology</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center py-16 opacity-50">
              {aiHealthy ? (
                <>
                  <span className="material-symbols-outlined text-4xl block mb-2 animate-bounce">
                    psychology
                  </span>
                  Compiling specialized banking fraud intelligence...
                </>
              ) : (
                <>
                  <span className="material-symbols-outlined text-4xl block mb-2 text-warning">
                    wifi_off
                  </span>
                  Ollama standby. Using heuristic risk scoring.
                </>
              )}
            </div>
          )}
        </div>
      </GlassPanel>

      {/* Granular Fraud Risk Breakdown */}
      <GlassPanel className="p-6 col-span-1 border-border bg-surface-variant/15 flex flex-col">
        <h4 className="text-xs font-semibold text-secondary tracking-wider uppercase mb-6 flex items-center gap-1.5">
          <span className="material-symbols-outlined text-sm">security_update_warning</span>
          FRAUD RISK BREAKDOWN
        </h4>
        
        <div className="space-y-5 flex-1">
          {Object.entries(fraudScores).map(([key, score]) => {
            if (key === 'overall_risk') return null
            const label = key.replace(/_/g, ' ').toUpperCase()
            return (
              <div key={key} className="space-y-1.5">
                <div className="flex justify-between items-end">
                  <span className="text-[10px] font-bold text-on-surface-variant/70 tracking-tighter">{label}</span>
                  <span className={`text-[10px] font-mono font-bold ${score > 70 ? 'text-error' : score > 40 ? 'text-warning' : 'text-success'}`}>
                    {score}%
                  </span>
                </div>
                <div className="h-1.5 w-full bg-surface-variant/30 rounded-full overflow-hidden border border-white/5">
                  <div 
                    className={`h-full transition-all duration-1000 ease-out ${
                      score > 70 ? 'bg-error shadow-[0_0_8px_rgba(255,82,82,0.4)]' : 
                      score > 40 ? 'bg-warning shadow-[0_0_8px_rgba(255,193,7,0.4)]' : 
                      'bg-success shadow-[0_0_8px_rgba(76,175,80,0.4)]'
                    }`}
                    style={{ width: `${score}%` }}
                  />
                </div>
              </div>
            )
          })}

          <div className="mt-8 p-4 rounded-lg border border-primary/20 bg-primary/5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-bold text-primary">OVERALL FRAUD RISK</span>
              <span className="text-lg font-mono font-black text-primary">{fraudScores.overall_risk}%</span>
            </div>
            <p className="text-[9px] text-on-surface-variant leading-tight opacity-70 italic">
              Score derived from cumulative heuristic markers and behavioral intelligence mapping.
            </p>
          </div>
        </div>
      </GlassPanel>
    </div>
  )
}
export default AICognitionConsole
