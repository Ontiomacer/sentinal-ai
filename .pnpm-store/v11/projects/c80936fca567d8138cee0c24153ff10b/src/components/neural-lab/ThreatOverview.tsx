import React from 'react'
import GlassPanel from '../ui/GlassPanel'
import { RiskAssessmentResponse } from '../../services/neuralApi'

interface ThreatOverviewProps {
  riskData: RiskAssessmentResponse | null
  totalFunctions: number
  totalIndicators: number
  totalPatterns: number
}

export const ThreatOverview: React.FC<ThreatOverviewProps> = ({
  riskData,
  totalFunctions,
  totalIndicators,
  totalPatterns,
}) => {
  const intel = riskData?.banking_intelligence
  const score = intel?.overall_risk ?? 0
  const severity = intel?.threat_classification ?? 'UNKNOWN'
  const confidence = intel?.confidence_score ?? 60
  const targetedApps = intel?.targeted_banking_apps ?? []
  const riskContributors = intel?.risk_factors ?? []
  
  // Gauge computations
  const radius = 50
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - (score / 100) * circumference

  const getGaugeColor = (val: number) => {
    if (val >= 75) return 'stroke-error'
    if (val >= 40) return 'stroke-warning'
    return 'stroke-success'
  }

  const getSeverityBg = (val: number) => {
    if (val >= 75) return 'border-error/20 text-error bg-error/5'
    if (val >= 40) return 'border-warning/20 text-warning bg-warning/5'
    return 'border-success/20 text-success bg-success/5'
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 select-none font-mono">
      {/* Risk Gauge Panel */}
      <GlassPanel className="p-6 flex flex-col items-center justify-center text-center col-span-1 border-border bg-surface-variant/10">
        <div className="w-full flex justify-between items-start mb-4">
          <span className="text-[9px] font-bold text-on-surface-variant bg-surface/80 px-2 py-0.5 rounded border border-border/40 uppercase tracking-tighter">
            BANKING FRAUD ANALYST
          </span>
          <span className={`text-[9px] font-bold px-2 py-0.5 rounded border uppercase tracking-tighter ${
            confidence >= 75 ? 'text-success border-success/20 bg-success/5' : 
            confidence >= 40 ? 'text-warning border-warning/20 bg-warning/5' : 
            'text-error border-error/20 bg-error/5'
          }`}>
            Confidence: {confidence >= 75 ? 'High' : confidence >= 40 ? 'Medium' : 'Low'}
          </span>
        </div>

        <h4 className="text-xs font-semibold text-on-surface-variant/70 tracking-wider uppercase mb-6 flex items-center gap-1">
          <span className="material-symbols-outlined text-sm">account_balance_wallet</span>
          FRAUD RISK INDEX
        </h4>
        
        {/* SVG Radial Gauge */}
        <div className="relative w-36 h-36 flex items-center justify-center mb-4">
          <svg className="w-full h-full transform -rotate-90">
            {/* Background ring */}
            <circle
              cx="72"
              cy="72"
              r={radius}
              className="stroke-border fill-none"
              strokeWidth="8"
            />
            {/* Value fill */}
            <circle
              cx="72"
              cy="72"
              r={radius}
              className={`fill-none transition-all duration-1000 ${getGaugeColor(score)}`}
              strokeWidth="8"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
            />
          </svg>
          <div className="absolute flex flex-col items-center justify-center">
            <span className="text-3xl font-bold tracking-tight text-on-surface">{score}</span>
            <span className="text-[10px] text-on-surface-variant opacity-60">FRAUD %</span>
          </div>
        </div>

        <div className={`border rounded-full px-4 py-1 text-xs font-bold ${getSeverityBg(score)} mb-2`}>
          {severity.toUpperCase()}
        </div>
        
        {riskContributors.length > 0 && (
          <div className="mt-4 w-full space-y-1">
            <p className="text-[8px] font-bold text-on-surface-variant/40 uppercase tracking-widest mb-2">Primary Risk Attribution</p>
            {riskContributors.slice(0, 3).map((c, i) => (
              <div key={i} className="flex justify-between items-center text-[9px] font-bold text-on-surface-variant/80 border-b border-white/5 pb-1">
                <span>{c.split(' +')[0]}</span>
                <span className="text-primary">+{c.split(' +')[1]}</span>
              </div>
            ))}
          </div>
        )}
      </GlassPanel>

      {/* Targeted Banking Apps Card */}
      <GlassPanel className="p-6 col-span-1 border-border bg-surface-variant/10">
        <h4 className="text-xs font-semibold text-on-surface-variant/70 tracking-wider uppercase mb-4 flex items-center gap-1">
          <span className="material-symbols-outlined text-sm">ads_click</span>
          TARGETED APPLICATIONS ({targetedApps.length})
        </h4>
        
        <div className="space-y-3">
          {targetedApps.length > 0 ? (
            targetedApps.map((app) => (
              <div key={app} className="flex items-center justify-between p-3 border border-primary/10 bg-primary/5 rounded-lg">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-primary text-sm">account_balance</span>
                  <span className="text-xs font-bold text-on-surface">{app}</span>
                </div>
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-error/20 text-error border border-error/30 font-black">TARGET</span>
              </div>
            ))
          ) : (
            <div className="text-xs text-on-surface-variant opacity-60 text-center py-12 flex flex-col items-center gap-2">
              <span className="material-symbols-outlined text-4xl opacity-20">search_off</span>
              No specific banking app signatures detected in the artifact surface.
            </div>
          )}
        </div>
      </GlassPanel>

      {/* Fraud Kill Chain Status */}
      <GlassPanel className="p-6 col-span-1 border-border bg-surface-variant/10 flex flex-col">
        <h4 className="text-xs font-semibold text-on-surface-variant/70 tracking-wider uppercase mb-3 flex items-center gap-1">
          <span className="material-symbols-outlined text-sm">account_tree</span>
          FRAUD KILL CHAIN PROGRESS
        </h4>
        
        <div className="flex-1 space-y-4 py-2">
          {[
            { label: 'Reconnaissance', active: true },
            { label: 'Weaponization', active: true },
            { label: 'Delivery', active: true },
            { label: 'Exploitation', active: score > 40 },
            { label: 'Credential Access', active: (intel?.fraud_scores?.credential_theft ?? 0) > 40 },
            { label: 'Financial Impact', active: score > 70 },
          ].map((step) => (
            <div key={step.label} className="flex items-center gap-3">
              <div className={`w-2 h-2 rounded-full ${step.active ? 'bg-error shadow-glow animate-pulse' : 'bg-border'}`} />
              <div className="flex-1 h-px bg-border/40" />
              <span className={`text-[10px] uppercase font-bold ${step.active ? 'text-on-surface' : 'text-on-surface-variant opacity-30'}`}>
                {step.label}
              </span>
            </div>
          ))}
        </div>
      </GlassPanel>

      {/* Quick Metrics row */}
      <div className="col-span-1 lg:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4 mt-2">
        <div className="p-4 border border-border bg-surface-variant/20 rounded-xl flex items-center gap-3">
          <span className="material-symbols-outlined text-primary text-2xl">function</span>
          <div>
            <span className="text-xl font-bold block text-on-surface">{totalFunctions}</span>
            <span className="text-[10px] text-on-surface-variant uppercase tracking-wider">SUSPICIOUS FUNCS</span>
          </div>
        </div>

        <div className="p-4 border border-border bg-surface-variant/20 rounded-xl flex items-center gap-3">
          <span className="material-symbols-outlined text-secondary text-2xl">warning</span>
          <div>
            <span className="text-xl font-bold block text-on-surface">{totalIndicators}</span>
            <span className="text-[10px] text-on-surface-variant uppercase tracking-wider">THREAT INDICATORS</span>
          </div>
        </div>

        <div className="p-4 border border-border bg-surface-variant/20 rounded-xl flex items-center gap-3">
          <span className="material-symbols-outlined text-warning text-2xl">flowsheet</span>
          <div>
            <span className="text-xl font-bold block text-on-surface">{totalPatterns}</span>
            <span className="text-[10px] text-on-surface-variant uppercase tracking-wider">BEHAVIOR PATTERNS</span>
          </div>
        </div>

        <div className="p-4 border border-border bg-surface-variant/20 rounded-xl flex items-center gap-3">
          <span className="material-symbols-outlined text-success text-2xl">hub</span>
          <div>
            <span className="text-xl font-bold block text-on-surface">
              {(riskData as any)?.yara_matches ?? 0}
            </span>
            <span className="text-[10px] text-on-surface-variant uppercase tracking-wider">YARA MATCHES</span>
          </div>
        </div>
      </div>
    </div>
  )
}
export default ThreatOverview
