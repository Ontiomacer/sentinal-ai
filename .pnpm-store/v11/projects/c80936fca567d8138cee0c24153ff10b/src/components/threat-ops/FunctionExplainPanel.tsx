/**
 * FUNCTION EXPLAIN PANEL
 * Deep intelligence view for clicked nodes
 * Shows: What it is, Why important, How contributes to malicious behavior, Evidence, Downstream findings
 */

import React, { useEffect, useState } from 'react'

interface Props {
  selectedNode: any
  analysisResult: any
}

const FunctionExplainPanel: React.FC<Props> = ({ selectedNode, analysisResult }) => {
  const [intelligence, setIntelligence] = useState<any>(null)

  useEffect(() => {
    if (!selectedNode) {
      setIntelligence(null)
      return
    }

    // Build intelligence report for selected node
    buildIntelligenceReport()
  }, [selectedNode, analysisResult])

  const buildIntelligenceReport = () => {
    const node = selectedNode
    const report: any = {
      type: node.type,
      label: node.label,
      layer: node.layer
    }

    // ROOT NODE
    if (node.type === 'root') {
      report.what = 'Android Application Package (APK) - The root artifact under investigation'
      report.why = 'Entry point for malware analysis. Contains all code, resources, and manifest.'
      report.evidence = [
        `Package: ${node.metadata.package}`,
        `SHA256: ${node.metadata.sha256?.substring(0, 16)}...`,
        `Version: ${node.metadata.version || 'Unknown'}`
      ]
      report.downstream = ['Manifest', 'DEX Files', 'Permissions', 'Components', 'Resources']
    }

    // MANIFEST
    else if (node.type === 'manifest') {
      report.what = 'AndroidManifest.xml - Application configuration and declarations'
      report.why = 'Declares permissions, components, and capabilities required by the app'
      report.evidence = [
        `Permissions: ${analysisResult.apk_analysis?.permissions?.length || 0}`,
        `Activities: ${analysisResult.apk_analysis?.activities?.length || 0}`,
        `Services: ${analysisResult.apk_analysis?.services?.length || 0}`
      ]
      report.downstream = ['Permissions', 'Activities', 'Services', 'Receivers']
    }

    // PERMISSION
    else if (node.type === 'permission') {
      const perms = node.metadata || []
      const dangerous = perms.filter((p: any) => p.category === 'dangerous' || p.category === 'system')
      report.what = 'Android Permissions - Capabilities requested by the application'
      report.why = dangerous.length > 0 
        ? `${dangerous.length} high-risk permissions detected. Enable access to sensitive device features.`
        : 'Standard permissions for app functionality'
      report.evidence = dangerous.slice(0, 5).map((p: any) => p.name)
      report.downstream = ['Function Calls', 'Behaviors', 'Threat Indicators']
      report.malicious = dangerous.some((p: any) => 
        ['BIND_ACCESSIBILITY_SERVICE', 'SYSTEM_ALERT_WINDOW', 'READ_SMS'].some(bad => p.name.includes(bad))
      )
    }

    // DEX
    else if (node.type === 'dex') {
      report.what = 'Dalvik Executable (DEX) - Compiled application code'
      report.why = 'Contains classes, methods, and executable logic. Primary target for malware analysis.'
      report.evidence = node.metadata.map((d: string) => d)
      report.downstream = ['Classes', 'Methods', 'Suspicious Functions']
    }

    // SUSPICIOUS FUNCTION
    else if (node.type === 'suspicious_function') {
      const func = node.metadata
      report.what = `Suspicious Function - ${func.function_name || func.name}`
      report.why = func.reason || 'Flagged by Suspicious Function Engine for malicious patterns'
      report.evidence = func.evidence || []
      report.riskScore = func.risk_score
      report.categories = func.categories || []
      report.malicious = func.risk_score > 70
      report.downstream = ['Behaviors', 'Threats', 'Risk Contribution']
      
      // Add AI explanation
      report.aiExplanation = `This function exhibits patterns commonly found in malware. ` +
        `Risk categories include: ${report.categories.join(', ')}. ` +
        `The function was identified through pattern matching against known malicious behaviors.`
    }

    // BEHAVIOR
    else if (node.type === 'behavior') {
      report.what = `Malicious Behavior - ${node.label}`
      report.why = 'Behavioral pattern detected from code analysis indicating potential malicious intent'
      report.evidence = node.metadata.evidence || []
      report.downstream = ['Threat Classification', 'Fraud Intent', 'Risk Score']
      report.malicious = true
      report.aiExplanation = `This behavior was reconstructed from function analysis. ` +
        `Multiple functions exhibit patterns consistent with ${node.label.toLowerCase()}.`
    }

    // THREAT
    else if (node.type === 'threat') {
      const threat = node.metadata
      report.what = `Threat Classification - ${node.label}`
      report.why = 'APK classified as malicious based on intelligence correlation'
      report.evidence = threat.evidence || []
      report.confidence = Math.round((threat.confidence || 0.85) * 100)
      report.downstream = ['Fraud Intent', 'Risk Score', 'Final Verdict']
      report.malicious = true
      report.aiExplanation = `Threat classification determined by Intelligence Engine. ` +
        `Confidence: ${report.confidence}%. Family: ${threat.threat_family || 'Generic Malware'}.`
    }

    // FRAUD
    else if (node.type === 'fraud') {
      const fraud = node.metadata
      report.what = 'Fraud Intent - Identified fraud objectives'
      report.why = 'APK designed to commit fraud based on behavioral analysis'
      report.evidence = (fraud.objectives || []).map((obj: any) => obj.objective || obj.name).slice(0, 5)
      report.downstream = ['Risk Score', 'Final Verdict']
      report.malicious = true
      report.aiExplanation = fraud.summary || 'Multiple fraud objectives detected from code and behavior analysis'
    }

    // RISK
    else if (node.type === 'risk') {
      const risk = node.metadata
      report.what = `Risk Score - ${risk.risk_score}/100`
      report.why = 'Aggregated risk from all malicious findings and behaviors'
      report.evidence = (risk.findings || []).slice(0, 5)
      report.contributors = (risk.contributors || []).map((c: any) => `${c.label}: +${c.score}`)
      report.downstream = ['Final Verdict']
      report.malicious = risk.risk_score > 50
    }

    // VERDICT
    else if (node.type === 'verdict') {
      const verdict = node.metadata
      report.what = `Final Verdict - ${verdict.severity}`
      report.why = 'Conclusion of autonomous AI investigation'
      report.evidence = [
        `Risk Score: ${verdict.riskScore}/100`,
        `Severity: ${verdict.severity}`,
        verdict.summary
      ].filter(Boolean)
      report.malicious = ['HIGH', 'CRITICAL'].includes(verdict.severity)
      report.aiExplanation = 'Investigation complete. All evidence correlated and analyzed.'
    }

    // DEFAULT
    else {
      report.what = `${node.type} - ${node.label}`
      report.why = 'APK artifact identified during analysis'
      report.evidence = ['Evidence available in metadata']
      report.downstream = []
    }

    setIntelligence(report)
  }

  if (!intelligence) {
    return (
      <div className="h-full bg-[#0f1419] border border-cyan-900/30 rounded flex items-center justify-center">
        <div className="text-center text-gray-600">
          <span className="material-symbols-outlined text-4xl mb-2 block opacity-30">info</span>
          <p className="text-xs font-mono">Click any node to view intelligence</p>
        </div>
      </div>
    )
  }

  return (
    <div className="h-full bg-[#0f1419] border border-cyan-900/30 rounded flex flex-col overflow-hidden">
      <div className="h-10 bg-[#1a1f2e] border-b border-cyan-900/30 flex items-center justify-between px-4">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-sm text-cyan-400">info</span>
          <span className="font-mono text-xs uppercase tracking-wider text-gray-400">
            Node Intelligence
          </span>
        </div>
        {intelligence.riskScore && (
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-gray-600">Risk:</span>
            <span className={`text-xs font-bold ${
              intelligence.riskScore > 75 ? 'text-red-400' :
              intelligence.riskScore > 50 ? 'text-yellow-400' :
              'text-green-400'
            }`}>
              {intelligence.riskScore}/100
            </span>
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Node Type Badge */}
        <div className="flex items-center gap-2">
          <span className={`px-2 py-1 rounded text-[10px] font-mono uppercase ${
            intelligence.malicious 
              ? 'bg-red-900/20 border border-red-700/30 text-red-400'
              : 'bg-cyan-900/20 border border-cyan-700/30 text-cyan-400'
          }`}>
            {intelligence.type}
          </span>
          <span className="text-xs font-mono text-gray-500">Layer {intelligence.layer}</span>
        </div>

        {/* WHAT IS THIS */}
        <div>
          <div className="text-[10px] font-mono text-cyan-400 uppercase mb-2 flex items-center gap-1">
            <span className="material-symbols-outlined text-xs">help</span>
            What is this?
          </div>
          <div className="text-sm text-gray-300 bg-[#1a1f2e] p-3 rounded border border-cyan-900/30">
            {intelligence.what}
          </div>
        </div>

        {/* WHY IMPORTANT */}
        <div>
          <div className="text-[10px] font-mono text-yellow-400 uppercase mb-2 flex items-center gap-1">
            <span className="material-symbols-outlined text-xs">priority_high</span>
            Why is it important?
          </div>
          <div className="text-sm text-gray-300 bg-[#1a1f2e] p-3 rounded border border-yellow-700/30">
            {intelligence.why}
          </div>
        </div>

        {/* EVIDENCE */}
        {intelligence.evidence && intelligence.evidence.length > 0 && (
          <div>
            <div className="text-[10px] font-mono text-green-400 uppercase mb-2 flex items-center gap-1">
              <span className="material-symbols-outlined text-xs">check_circle</span>
              Evidence
            </div>
            <div className="space-y-1">
              {intelligence.evidence.map((ev: string, idx: number) => (
                <div
                  key={idx}
                  className="text-xs font-mono text-gray-400 bg-[#1a1f2e] px-3 py-2 rounded border border-green-700/30"
                >
                  • {ev}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* CATEGORIES */}
        {intelligence.categories && intelligence.categories.length > 0 && (
          <div>
            <div className="text-[10px] font-mono text-red-400 uppercase mb-2">Risk Categories</div>
            <div className="flex flex-wrap gap-1">
              {intelligence.categories.map((cat: string, idx: number) => (
                <span
                  key={idx}
                  className="px-2 py-1 bg-red-900/20 border border-red-700/30 rounded text-[10px] font-mono text-red-400"
                >
                  {cat}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* CONTRIBUTORS */}
        {intelligence.contributors && intelligence.contributors.length > 0 && (
          <div>
            <div className="text-[10px] font-mono text-orange-400 uppercase mb-2">Risk Contributors</div>
            <div className="space-y-1">
              {intelligence.contributors.map((contrib: string, idx: number) => (
                <div
                  key={idx}
                  className="text-xs font-mono text-gray-400 bg-[#1a1f2e] px-3 py-2 rounded border border-orange-700/30"
                >
                  • {contrib}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* AI EXPLANATION */}
        {intelligence.aiExplanation && (
          <div>
            <div className="text-[10px] font-mono text-purple-400 uppercase mb-2 flex items-center gap-1">
              <span className="material-symbols-outlined text-xs">psychology</span>
              AI Analysis
            </div>
            <div className="text-xs text-gray-300 leading-relaxed bg-purple-900/10 p-3 rounded border border-purple-700/30">
              {intelligence.aiExplanation}
            </div>
          </div>
        )}

        {/* DOWNSTREAM FINDINGS */}
        {intelligence.downstream && intelligence.downstream.length > 0 && (
          <div>
            <div className="text-[10px] font-mono text-blue-400 uppercase mb-2 flex items-center gap-1">
              <span className="material-symbols-outlined text-xs">arrow_forward</span>
              Downstream Findings
            </div>
            <div className="flex flex-wrap gap-1">
              {intelligence.downstream.map((item: string, idx: number) => (
                <span
                  key={idx}
                  className="px-2 py-1 bg-blue-900/20 border border-blue-700/30 rounded text-[10px] font-mono text-blue-400"
                >
                  → {item}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* CONFIDENCE */}
        {intelligence.confidence && (
          <div className="pt-3 border-t border-cyan-900/30">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-gray-600 uppercase">Confidence</span>
              <span className="text-sm font-bold text-cyan-400">{intelligence.confidence}%</span>
            </div>
            <div className="w-full bg-[#1a1f2e] rounded-full h-2 mt-2">
              <div
                className="h-2 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500"
                style={{ width: `${intelligence.confidence}%` }}
              ></div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default FunctionExplainPanel
