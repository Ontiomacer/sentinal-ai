/**
 * AI DYNAMIC ANALYST
 * AI-powered runtime behavior analysis using Qwen3-4B
 * Backend Integration: POST /api/v1/device-lab/analyze-runtime
 */

import React, { useState, useEffect } from 'react'

interface Props {
  events: any[]
  deployedAPK: string | null
}

interface Analysis {
  summary: string
  threats: ThreatIndicator[]
  behavior: BehaviorPattern[]
  confidence: number
  verdict: 'benign' | 'suspicious' | 'malicious'
}

interface ThreatIndicator {
  type: string
  description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  evidence: string[]
  confidence: number
}

interface BehaviorPattern {
  pattern: string
  description: string
  occurrences: number
  riskLevel: 'low' | 'medium' | 'high'
}

const AIDynamicAnalyst: React.FC<Props> = ({ events, deployedAPK }) => {
  const [analysis, setAnalysis] = useState<Analysis | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [autoAnalyze, setAutoAnalyze] = useState(true)

  // Auto-analyze when events accumulate
  useEffect(() => {
    if (!deployedAPK || !autoAnalyze || events.length === 0) return

    const timer = setTimeout(() => {
      analyzeRuntime()
    }, 5000) // Analyze every 5 seconds

    return () => clearTimeout(timer)
  }, [events, deployedAPK, autoAnalyze])

  const analyzeRuntime = async () => {
    if (!deployedAPK) return

    setIsAnalyzing(true)
    setAnalysis(null)
    setIsAnalyzing(false)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-500'
      case 'high': return 'text-orange-500'
      case 'medium': return 'text-yellow-500'
      case 'low': return 'text-blue-500'
      default: return 'text-gray-500'
    }
  }

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case 'malicious': return 'text-red-400 bg-red-900/20 border-red-700'
      case 'suspicious': return 'text-yellow-400 bg-yellow-900/20 border-yellow-700'
      case 'benign': return 'text-green-400 bg-green-900/20 border-green-700'
      default: return 'text-gray-400 bg-gray-900/20 border-gray-700'
    }
  }

  return (
    <div className="h-full bg-[#0f1419] border border-green-900/30 rounded flex flex-col overflow-hidden">
      {/* Header */}
      <div className="h-10 bg-[#1a1f2e] border-b border-green-900/30 flex items-center justify-between px-4">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-sm text-green-400">psychology</span>
          <span className="font-mono text-xs uppercase tracking-wider text-gray-400">
            AI Dynamic Analyst
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoAnalyze(!autoAnalyze)}
            className={`px-2 py-1 rounded text-[10px] font-mono transition-colors ${
              autoAnalyze
                ? 'bg-green-500/20 border border-green-500/50 text-green-400'
                : 'bg-[#0f1419] border border-green-900/30 text-gray-600'
            }`}
          >
            Auto
          </button>
          <button
            onClick={analyzeRuntime}
            disabled={!deployedAPK || isAnalyzing}
            className="px-2 py-1 bg-[#0f1419] border border-green-900/30 hover:border-green-700 disabled:opacity-50 disabled:cursor-not-allowed rounded text-[10px] font-mono text-gray-400 hover:text-green-400 transition-colors"
          >
            {isAnalyzing ? 'Analyzing...' : 'Analyze Now'}
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {!deployedAPK ? (
          <div className="h-full flex items-center justify-center">
            <div className="text-center">
              <span className="material-symbols-outlined text-3xl text-gray-700 mb-2 block">
                psychology
              </span>
              <p className="text-xs font-mono text-gray-600">Deploy APK to start AI analysis</p>
            </div>
          </div>
        ) : isAnalyzing ? (
          <div className="h-full flex items-center justify-center">
            <div className="text-center">
              <div className="w-16 h-16 mx-auto mb-4 border-4 border-green-500/30 border-t-green-500 rounded-full animate-spin"></div>
              <p className="text-sm font-mono text-green-400 mb-2">AI Analysis in Progress</p>
              <p className="text-xs font-mono text-gray-600">
                Qwen3-4B analyzing runtime behavior...
              </p>
            </div>
          </div>
        ) : analysis ? (
          <>
            {/* Verdict */}
            <div className={`p-4 rounded border ${getVerdictColor(analysis.verdict)}`}>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-xl">shield</span>
                  <span className="text-sm font-mono uppercase font-bold">{analysis.verdict}</span>
                </div>
                <div className="text-xs font-mono">
                  Confidence: {(analysis.confidence * 100).toFixed(0)}%
                </div>
              </div>
              <p className="text-xs leading-relaxed">{analysis.summary}</p>
            </div>

            {/* Threat Indicators */}
            <div>
              <div className="text-[10px] font-mono text-gray-600 uppercase mb-2">
                Threat Indicators ({analysis.threats.length})
              </div>
              <div className="space-y-2">
                {analysis.threats.map((threat, idx) => (
                  <div key={idx} className="p-3 bg-[#1a1f2e] border border-green-900/30 rounded">
                    <div className="flex items-start justify-between mb-2">
                      <div>
                        <div className="text-xs font-mono text-white mb-1">{threat.type}</div>
                        <div className="text-[10px] font-mono text-gray-400">{threat.description}</div>
                      </div>
                      <div className="flex flex-col items-end gap-1">
                        <span className={`text-[10px] font-mono uppercase ${getSeverityColor(threat.severity)}`}>
                          {threat.severity}
                        </span>
                        <span className="text-[10px] font-mono text-gray-600">
                          {(threat.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                    </div>
                    <div className="mt-2 space-y-1">
                      <div className="text-[10px] font-mono text-gray-600 uppercase mb-1">Evidence:</div>
                      {threat.evidence.map((ev, evIdx) => (
                        <div key={evIdx} className="flex items-start gap-2 text-[10px] font-mono text-gray-500">
                          <span className="material-symbols-outlined text-xs text-gray-600">chevron_right</span>
                          <span className="flex-1">{ev}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Behavior Patterns */}
            <div>
              <div className="text-[10px] font-mono text-gray-600 uppercase mb-2">
                Behavior Patterns ({analysis.behavior.length})
              </div>
              <div className="space-y-2">
                {analysis.behavior.map((behavior, idx) => (
                  <div key={idx} className="p-3 bg-[#1a1f2e] border border-green-900/30 rounded">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono text-white">{behavior.pattern}</span>
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] font-mono uppercase ${
                          behavior.riskLevel === 'high' ? 'text-red-400' :
                          behavior.riskLevel === 'medium' ? 'text-yellow-400' :
                          'text-blue-400'
                        }`}>
                          {behavior.riskLevel}
                        </span>
                        <span className="px-2 py-0.5 bg-green-900/30 rounded text-[10px] font-mono text-green-400">
                          {behavior.occurrences}x
                        </span>
                      </div>
                    </div>
                    <p className="text-[10px] font-mono text-gray-500">{behavior.description}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* AI Model Info */}
            <div className="p-3 bg-[#1a1f2e] border border-green-900/30 rounded">
              <div className="flex items-center gap-2 mb-2">
                <span className="material-symbols-outlined text-sm text-green-400">smart_toy</span>
                <span className="text-[10px] font-mono text-gray-600 uppercase">AI Model</span>
              </div>
              <div className="text-xs font-mono text-gray-400">
                Qwen3-4B Dynamic Analysis Engine
              </div>
              <div className="text-[10px] font-mono text-gray-600 mt-1">
                Correlates runtime behavior with static analysis results
              </div>
            </div>
          </>
        ) : (
          <div className="h-full flex items-center justify-center">
            <div className="text-center">
              <span className="material-symbols-outlined text-3xl text-gray-700 mb-2 block">
                pending
              </span>
              <p className="text-xs font-mono text-gray-600 mb-2">No analysis available</p>
              <button
                onClick={analyzeRuntime}
                className="px-3 py-1.5 bg-green-500/20 border border-green-500/50 hover:bg-green-500/30 rounded text-xs font-mono text-green-400 transition-colors"
              >
                Start Analysis
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Status Bar */}
      {deployedAPK && (
        <div className="h-8 bg-[#1a1f2e] border-t border-green-900/30 flex items-center justify-between px-4">
          <div className="flex items-center gap-2">
            {autoAnalyze && (
              <>
                <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
                <span className="text-[10px] font-mono text-green-400">
                  Auto-analysis enabled
                </span>
              </>
            )}
          </div>
          <div className="text-[10px] font-mono text-gray-600">
            Events monitored: {events.length}
          </div>
        </div>
      )}
    </div>
  )
}

export default AIDynamicAnalyst
