import React, { useState, useEffect } from 'react'

interface Hypothesis {
  id: string
  title: string
  confidence: number
  status: 'active' | 'confirmed' | 'rejected'
}

interface Props {
  evidenceId?: string
  analysisResult?: any
  selectedNode: string | null
}

const AIInvestigator: React.FC<Props> = ({ evidenceId, analysisResult }) => {
  const [hypotheses, setHypotheses] = useState<Hypothesis[]>([])
  const [question, setQuestion] = useState<string>('')
  const [messages, setMessages] = useState<Array<{ role: 'user' | 'assistant'; content: any }>>([])

  useEffect(() => {
    if (!analysisResult) {
      setHypotheses([])
      setMessages([])
      return
    }

    // Build hypotheses from analysis
    const realHypotheses: Hypothesis[] = []
    
    // Extract threat type
    if (analysisResult.threat_classification) {
      const confidence = Math.round((analysisResult.threat_classification.confidence || 0.9) * 100)
      realHypotheses.push({
        id: 'h-threat',
        title: analysisResult.threat_classification.threat_type,
        confidence,
        status: confidence > 80 ? 'confirmed' : 'active'
      })
    }

    // Extract fraud objectives
    if (analysisResult.fraud_intent?.objectives) {
      analysisResult.fraud_intent.objectives.forEach((obj: any, idx: number) => {
        const confidence = Math.round((obj.confidence || 0.8) * 100)
        realHypotheses.push({
          id: `h-fraud-${idx}`,
          title: obj.objective || obj.name || `Fraud Objective ${idx + 1}`,
          confidence,
          status: confidence > 75 ? 'confirmed' : 'active'
        })
      })
    }

    // Generic threat hypothesis based on risk score
    const riskScore = analysisResult.threat_assessment?.risk_score || 
                     analysisResult.risk_assessment?.risk_score || 0
    if (riskScore > 50 && realHypotheses.length === 0) {
      realHypotheses.push({
        id: 'h-generic',
        title: 'Malicious Intent',
        confidence: riskScore,
        status: riskScore > 75 ? 'confirmed' : 'active'
      })
    }

    setHypotheses(realHypotheses)

    // Initial AI response based on analysis
    const initialConclusion = generateInitialConclusion()
    if (initialConclusion) {
      setMessages([{ role: 'assistant', content: initialConclusion }])
    }
  }, [evidenceId, analysisResult])

  const generateInitialConclusion = () => {
    if (!analysisResult) return null

    const evidence: string[] = []
    const threatType = analysisResult.threat_classification?.threat_type || 'Unknown Threat'
    const riskScore = analysisResult.threat_assessment?.risk_score || 
                     analysisResult.risk_assessment?.risk_score || 0

    // Extract evidence
    if (analysisResult.top_suspicious_functions) {
      analysisResult.top_suspicious_functions.slice(0, 3).forEach((func: any) => {
        evidence.push(func.function_name || func.name)
      })
    }

    if (analysisResult.apk_analysis?.permissions) {
      const dangerous = analysisResult.apk_analysis.permissions
        .filter((p: any) => p.category === 'dangerous')
        .slice(0, 2)
      dangerous.forEach((p: any) => {
        evidence.push(p.name.split('.').pop() || p.name)
      })
    }

    const reasoning = analysisResult.threat_classification?.evidence?.join('. ') ||
                     analysisResult.threat_assessment?.summary ||
                     'No Data Available'

    return {
      conclusion: threatType,
      evidence,
      reasoning,
      confidence: riskScore
    }
  }

  const handleAskQuestion = (e: React.FormEvent) => {
    e.preventDefault()
    if (!question.trim()) return

    // Add user question
    setMessages(prev => [...prev, { role: 'user', content: question }])

    setMessages(prev => [...prev, {
      role: 'assistant',
      content: {
        conclusion: 'No Data Available',
        evidence: [],
        reasoning: 'No connected AI investigator response is available for this evidence.',
        confidence: 0
      }
    }])
    setQuestion('')
  }

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Hypotheses Section */}
      <div className="p-4 border-b border-white/10">
        <h3 className="font-mono text-xs text-on-surface-variant uppercase tracking-wider mb-3 flex items-center gap-2">
          <span className="material-symbols-outlined text-purple-400">lightbulb</span>
          Evolving Hypotheses
        </h3>
        <div className="space-y-2">
          {hypotheses.map((hyp) => (
            <div
              key={hyp.id}
              className={`p-2 rounded border transition-all duration-500 ${
                hyp.status === 'confirmed'
                  ? 'border-green-500/30 bg-green-500/5'
                  : hyp.status === 'active'
                  ? 'border-yellow-500/30 bg-yellow-500/5'
                  : 'border-red-500/30 bg-red-500/5 opacity-50'
              }`}
            >
              <div className="flex justify-between items-center">
                <p className="text-xs text-white truncate">{hyp.title}</p>
                <span className="text-xs font-mono font-bold text-white">
                  {hyp.confidence}%
                </span>
              </div>
              <div className="w-full bg-white/10 rounded-full h-1 mt-1">
                <div
                  className={`h-1 rounded-full transition-all duration-500 ${
                    hyp.confidence > 80 ? 'bg-green-500' :
                    hyp.confidence > 50 ? 'bg-yellow-500' :
                    'bg-cyan-500'
                  }`}
                  style={{ width: `${hyp.confidence}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Chat/Investigation Section */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((msg, i) => (
            <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-full p-3 rounded-lg ${
                msg.role === 'user'
                  ? 'bg-cyan-500/10 border border-cyan-500/20'
                  : 'bg-surface-container border border-white/10'
              }`}>
                {msg.role === 'assistant' ? (
                  <div className="space-y-2">
                    <div>
                      <p className="text-xs font-mono text-purple-400 uppercase tracking-wider">
                        Conclusion
                      </p>
                      <p className="text-sm text-white">{msg.content.conclusion}</p>
                    </div>
                    <div>
                      <p className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
                        Evidence
                      </p>
                      <ul className="text-xs text-on-surface-variant space-y-1">
                        {msg.content.evidence.map((e: string, j: number) => (
                          <li key={j} className="flex items-center gap-2">
                            <span className="material-symbols-outlined text-yellow-400 text-sm">check</span>
                            {e}
                          </li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <p className="text-xs font-mono text-on-surface-variant uppercase tracking-wider">
                        Reasoning
                      </p>
                      <p className="text-xs text-on-surface-variant">{msg.content.reasoning}</p>
                    </div>
                    <div className="flex items-center justify-end gap-2">
                      <span className="text-xs font-mono text-on-surface-variant">Confidence:</span>
                      <span className="text-sm font-bold text-white">{msg.content.confidence}%</span>
                    </div>
                  </div>
                ) : (
                  <p className="text-sm text-white">{msg.content}</p>
                )}
              </div>
            </div>
          ))}
        </div>

        <div className="p-4 border-t border-white/10">
          <form onSubmit={handleAskQuestion} className="flex gap-2">
            <input
              type="text"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Ask the investigator..."
              className="flex-1 bg-white/5 border border-white/10 rounded px-3 py-2 text-sm text-white placeholder:text-on-surface-variant focus:outline-none focus:border-cyan-500/50"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 border border-cyan-500/30 rounded transition-colors"
            >
              <span className="material-symbols-outlined">send</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}

export default AIInvestigator
