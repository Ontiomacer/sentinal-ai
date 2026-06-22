/**
 * Device Security Assessment Panel
 * Comprehensive security analysis of connected device
 */

import React, { useState, useEffect } from 'react'

interface SecurityAssessment {
  risk_score: number
  trust_score: number
  risk_level: string
  findings: Array<{
    severity: string
    category: string
    description: string
    recommendation: string
  }>
  categories: any
}

interface Props {
  device: any
}

const SecurityAssessment: React.FC<Props> = ({ device }) => {
  const [assessment, setAssessment] = useState<SecurityAssessment | null>(null)
  const [loading, setLoading] = useState(false)

  const runAssessment = async () => {
    if (!device) return
    
    setLoading(true)
    try {
      const response = await fetch(`/api/v1/device-lab/security/assess?serial=${device.serial}`)
      const data = await response.json()
      
      if (data.success) {
        setAssessment(data.assessment)
      }
    } catch (error) {
      console.error('Failed to run assessment:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (device) {
      runAssessment()
    }
  }, [device])

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'LOW': return 'text-green-400 bg-green-900/20 border-green-700'
      case 'MEDIUM': return 'text-yellow-400 bg-yellow-900/20 border-yellow-700'
      case 'HIGH': return 'text-orange-400 bg-orange-900/20 border-orange-700'
      case 'CRITICAL': return 'text-red-400 bg-red-900/20 border-red-700'
      default: return 'text-gray-400 bg-gray-900/20 border-gray-700'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'HIGH': return 'text-red-400'
      case 'MEDIUM': return 'text-yellow-400'
      case 'LOW': return 'text-blue-400'
      default: return 'text-gray-400'
    }
  }

  return (
    <div className="h-full flex flex-col bg-[#0f1419]">
      {/* Header */}
      <div className="h-12 bg-[#1a1f2e] border-b border-green-900/30 flex items-center justify-between px-4 flex-shrink-0">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-sm text-green-400">shield</span>
          <span className="font-mono text-xs uppercase tracking-wider text-gray-400">
            Security Assessment
          </span>
        </div>
        
        <button
          onClick={runAssessment}
          disabled={loading || !device}
          className="px-3 py-1.5 bg-green-500/20 border border-green-500/50 hover:bg-green-500/30 rounded text-xs font-mono text-green-400 transition-colors disabled:opacity-50"
        >
          {loading ? 'Analyzing...' : 'Run Assessment'}
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {loading ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <div className="w-16 h-16 mx-auto mb-4 border-4 border-green-500/30 border-t-green-500 rounded-full animate-spin"></div>
              <p className="text-sm text-gray-500 mb-2">Analyzing device security...</p>
              <p className="text-xs text-gray-600">This may take a minute</p>
            </div>
          </div>
        ) : assessment ? (
          <div className="space-y-4">
            {/* Risk Score */}
            <div className={`p-4 rounded-lg border ${getRiskColor(assessment.risk_level)}`}>
              <div className="flex items-center justify-between mb-3">
                <div>
                  <div className="text-xs uppercase tracking-wider mb-1">Risk Level</div>
                  <div className="text-2xl font-bold">{assessment.risk_level}</div>
                </div>
                <div className="text-right">
                  <div className="text-xs uppercase tracking-wider mb-1">Risk Score</div>
                  <div className="text-2xl font-bold">{assessment.risk_score}/100</div>
                </div>
              </div>
              <div className="w-full bg-[#0a0a0f] rounded-full h-2">
                <div 
                  className={`h-2 rounded-full transition-all ${
                    assessment.risk_score < 20 ? 'bg-green-500' :
                    assessment.risk_score < 50 ? 'bg-yellow-500' :
                    assessment.risk_score < 75 ? 'bg-orange-500' : 'bg-red-500'
                  }`}
                  style={{ width: `${assessment.risk_score}%` }}
                ></div>
              </div>
            </div>

            {/* Trust Score */}
            <div className="p-4 bg-[#1a1f2e] rounded-lg border border-green-900/30">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wider text-gray-400">Device Trust Score</span>
                <span className="text-xl font-bold text-green-400">{assessment.trust_score}/100</span>
              </div>
            </div>

            {/* Findings */}
            {assessment.findings && assessment.findings.length > 0 && (
              <div className="space-y-2">
                <div className="text-xs uppercase tracking-wider text-gray-400 mb-2">
                  Security Findings ({assessment.findings.length})
                </div>
                
                {assessment.findings.map((finding, idx) => (
                  <div key={idx} className="p-3 bg-[#1a1f2e] rounded border border-green-900/30">
                    <div className="flex items-start gap-3 mb-2">
                      <span className={`material-symbols-outlined text-base ${getSeverityColor(finding.severity)}`}>
                        {finding.severity === 'HIGH' ? 'error' : finding.severity === 'MEDIUM' ? 'warning' : 'info'}
                      </span>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-medium text-gray-300">{finding.category}</span>
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                            finding.severity === 'HIGH' ? 'bg-red-900/30 text-red-400' :
                            finding.severity === 'MEDIUM' ? 'bg-yellow-900/30 text-yellow-400' :
                            'bg-blue-900/30 text-blue-400'
                          }`}>
                            {finding.severity}
                          </span>
                        </div>
                        <p className="text-xs text-gray-500 mb-2">{finding.description}</p>
                        <div className="flex items-start gap-2 p-2 bg-[#0f1419] rounded">
                          <span className="material-symbols-outlined text-xs text-green-400 mt-0.5">lightbulb</span>
                          <p className="text-xs text-gray-400">{finding.recommendation}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Categories Summary */}
            <div className="grid grid-cols-2 gap-3">
              {assessment.categories.sideloaded_apps && (
                <div className="p-3 bg-[#1a1f2e] rounded border border-green-900/30">
                  <div className="text-xs text-gray-600 mb-1">Sideloaded Apps</div>
                  <div className="text-xl font-bold text-orange-400">{assessment.categories.sideloaded_apps.count}</div>
                </div>
              )}
              
              {assessment.categories.accessibility_services && (
                <div className="p-3 bg-[#1a1f2e] rounded border border-green-900/30">
                  <div className="text-xs text-gray-600 mb-1">Accessibility Services</div>
                  <div className="text-xl font-bold text-red-400">{assessment.categories.accessibility_services.count}</div>
                </div>
              )}
              
              {assessment.categories.overlay_windows && (
                <div className="p-3 bg-[#1a1f2e] rounded border border-green-900/30">
                  <div className="text-xs text-gray-600 mb-1">Overlay Windows</div>
                  <div className="text-xl font-bold text-red-400">{assessment.categories.overlay_windows.count}</div>
                </div>
              )}
              
              {assessment.categories.dangerous_permissions && (
                <div className="p-3 bg-[#1a1f2e] rounded border border-green-900/30">
                  <div className="text-xs text-gray-600 mb-1">Dangerous Permissions</div>
                  <div className="text-xl font-bold text-yellow-400">{assessment.categories.dangerous_permissions.count}</div>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <span className="material-symbols-outlined text-6xl text-gray-700 mb-4 block">shield</span>
              <p className="text-sm text-gray-600 mb-3">No assessment data</p>
              <button
                onClick={runAssessment}
                disabled={!device}
                className="px-4 py-2 bg-green-500/20 border border-green-500/50 hover:bg-green-500/30 rounded text-sm font-mono text-green-400 transition-colors disabled:opacity-50"
              >
                Run Security Assessment
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default SecurityAssessment
