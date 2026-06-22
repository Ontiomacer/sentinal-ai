import React, { useState, useEffect } from 'react'

interface EscalationStep {
  score: number
  reason: string
  evidence: string[]
}

interface Props {
  evidenceId?: string
  analysisResult?: any
}

const RiskEscalationEngine: React.FC<Props> = ({ evidenceId, analysisResult }) => {
  const [steps, setSteps] = useState<EscalationStep[]>([])
  const [currentScore, setCurrentScore] = useState(0)

  useEffect(() => {
    if (!analysisResult) {
      setSteps([])
      setCurrentScore(0)
      return
    }

    buildEscalationSteps()
  }, [evidenceId, analysisResult])

  const buildEscalationSteps = () => {
    const realSteps: EscalationStep[] = []
    
    // Step 1: Initial Analysis
    realSteps.push({
      score: 20,
      reason: 'Initial Static Analysis Complete',
      evidence: ['APK parsed successfully', 'Manifest extracted']
    })

    // Step 2: Permissions
    const dangerousPerms = analysisResult.apk_analysis?.permissions?.filter(
      (p: any) => p.category === 'dangerous' || p.category === 'system'
    ) || []
    
    if (dangerousPerms.length > 0) {
      realSteps.push({
        score: 45,
        reason: `${dangerousPerms.length} Dangerous Permissions Detected`,
        evidence: dangerousPerms.slice(0, 2).map((p: any) => p.name.split('.').pop() || p.name)
      })
    }

    // Step 3: Suspicious Functions
    if (analysisResult.top_suspicious_functions && analysisResult.top_suspicious_functions.length > 0) {
      const topFunc = analysisResult.top_suspicious_functions[0]
      const funcScore = Math.round((topFunc.risk_score || 0.65) * 100)
      realSteps.push({
        score: funcScore,
        reason: `${topFunc.risk_category || 'Suspicious'} Functions Identified`,
        evidence: analysisResult.top_suspicious_functions.slice(0, 2).map(
          (f: any) => f.function_name || f.name
        )
      })
    }

    // Step 4: Final Risk Score
    const finalScore = analysisResult.threat_assessment?.risk_score || 
                      analysisResult.risk_assessment?.risk_score || 0
    
    if (finalScore > 50) {
      const severity = analysisResult.threat_assessment?.severity || 
                      analysisResult.risk_assessment?.severity || 'MEDIUM'
      const findings = analysisResult.threat_assessment?.findings || 
                      analysisResult.risk_assessment?.findings || []
      
      realSteps.push({
        score: finalScore,
        reason: `${severity} Threat Confirmed`,
        evidence: findings.slice(0, 2)
      })
    }

    // Animate escalation
    setSteps(realSteps)
    let stepIndex = 0
    setCurrentScore(0)
    
    const interval = setInterval(() => {
      if (stepIndex < realSteps.length) {
        setCurrentScore(realSteps[stepIndex].score)
        stepIndex++
      } else {
        clearInterval(interval)
      }
    }, 1500)

    return () => clearInterval(interval)
  }

  const getColor = (score: number) => {
    if (score < 30) return '#10b981' // green
    if (score < 60) return '#f59e0b' // yellow
    if (score < 85) return '#f97316' // orange
    return '#ef4444' // red
  }

  return (
    <div className="flex-1 flex items-center gap-8 px-8 overflow-hidden">
      {/* Current Risk Display */}
      <div className="flex flex-col items-center">
        <div className="text-xs font-mono text-on-surface-variant uppercase tracking-widest mb-2">
          Current Risk Score
        </div>
        <div className="relative w-32 h-32">
          <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
            <circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke="rgba(255,255,255,0.1)"
              strokeWidth="8"
            />
            <circle
              cx="50"
              cy="50"
              r="45"
              fill="none"
              stroke={getColor(currentScore)}
              strokeWidth="8"
              strokeDasharray="283"
              strokeDashoffset={283 - (283 * currentScore) / 100}
              className="transition-all duration-1000 ease-out"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-4xl font-display-xl text-white" style={{ color: getColor(currentScore) }}>
              {currentScore}
            </span>
            <span className="text-xs text-on-surface-variant uppercase tracking-wider">
              Risk Score
            </span>
          </div>
        </div>
      </div>

      {/* Escalation Timeline */}
      <div className="flex-1 flex items-center overflow-x-auto">
        {steps.map((step, index) => {
          const isCompleted = currentScore >= step.score
          return (
            <div
              key={index}
              className={`flex items-center transition-all duration-700 ${
                isCompleted ? 'opacity-100' : 'opacity-40'
              }`}
            >
              {/* Step Card */}
              <div className="w-48 bg-surface-container rounded-lg border border-white/10 p-3">
                <div className="flex items-center justify-between mb-2">
                  <span
                    className="text-lg font-display-xl"
                    style={{ color: isCompleted ? getColor(step.score) : 'rgba(255,255,255,0.5)' }}
                  >
                    {step.score}
                  </span>
                  {isCompleted && (
                    <span className="material-symbols-outlined text-green-400">
                      check_circle
                    </span>
                  )}
                </div>
                <p className="text-xs text-white mb-2">
                  {step.reason}
                </p>
                <div className="space-y-1">
                  {step.evidence.map((e, i) => (
                    <div key={i} className="flex items-center gap-2 text-[10px] text-on-surface-variant">
                      <span className="material-symbols-outlined text-yellow-400 text-[12px]">
                        info
                      </span>
                      {e}
                    </div>
                  ))}
                </div>
              </div>

              {/* Arrow to next step */}
              {index < steps.length - 1 && (
                <div className="mx-4">
                  <span className="material-symbols-outlined text-white/30">
                    arrow_forward
                  </span>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default RiskEscalationEngine
