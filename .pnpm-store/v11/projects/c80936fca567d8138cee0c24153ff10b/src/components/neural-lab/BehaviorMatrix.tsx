import React, { useState } from 'react'
import GlassPanel from '../ui/GlassPanel'

interface BehavioralPattern {
  pattern_name: string
  confidence: number
  evidence: string[]
  attack_chain: string[]
  fraud_indicators: string[]
  ai_explanation: string
}

interface BehaviorMatrixProps {
  patterns: BehavioralPattern[]
  yaraMatches: any[]
}

interface VectorDetail {
  id: string
  name: string
  icon: string
  description: string
  fallbackPatterns: string[]
}

const FRAUD_VECTORS: VectorDetail[] = [
  {
    id: 'overlay',
    name: 'Overlay Hijacking',
    icon: 'open_in_new',
    description: 'Injects fake login layouts over financial apps to harvest authentication codes.',
    fallbackPatterns: ['overlay', 'alert_window', 'windowmanager'],
  },
  {
    id: 'accessibility',
    name: 'Accessibility Abuse',
    icon: 'accessibility',
    description: 'Abuses Android Accessibility APIs to read UI elements and perform automated clicks.',
    fallbackPatterns: ['accessibility', 'bind_accessibility_service', 'nodeinfo'],
  },
  {
    id: 'sms',
    name: 'SMS Interception',
    icon: 'sms',
    description: 'Intercepts incoming SMS messages to steal OTP bank authorization codes.',
    fallbackPatterns: ['sms', 'receive_sms', 'telephony', 'receiver'],
  },
  {
    id: 'keylog',
    name: 'Input keylogging',
    icon: 'keyboard',
    description: 'Captures keystrokes or text modifications to intercept secure user credentials.',
    fallbackPatterns: ['key', 'keyboard', 'textwatcher', 'ontextchange'],
  },
  {
    id: 'c2',
    name: 'C2 Backdoor',
    icon: 'dns',
    description: 'Establishes covert communication channels to sync telemetry or fetch secondary payloads.',
    fallbackPatterns: ['c2', 'okhttp', 'httpurlconnection', 'websocket'],
  },
  {
    id: 'evasion',
    name: 'Anti-Analysis',
    icon: 'visibility_off',
    description: 'Checks for emulation environments or debugger attachments to bypass detection.',
    fallbackPatterns: ['emulator', 'root', 'debugger', 'isdebuggerconnected'],
  },
]

export const BehaviorMatrix: React.FC<BehaviorMatrixProps> = ({ patterns, yaraMatches }) => {
  const [expandedVector, setExpandedVector] = useState<string | null>(null)

  const checkDetection = (vector: VectorDetail) => {
    // 1. Check patterns
    const foundPattern = patterns.find((p) =>
      p.pattern_name.toLowerCase().includes(vector.id) ||
      p.pattern_name.toLowerCase().includes(vector.name.toLowerCase().split(' ')[0])
    )
    if (foundPattern) {
      return { detected: true, confidence: foundPattern.confidence * 100, evidence: foundPattern.evidence }
    }

    // 2. Check YARA matches
    const foundYara = yaraMatches.find((m) =>
      m.rule_name.toLowerCase().includes(vector.id) ||
      m.tags?.some((t: string) => t.toLowerCase() === vector.id)
    )
    if (foundYara) {
      return {
        detected: true,
        confidence: 85,
        evidence: foundYara.matched_strings || [foundYara.description],
      }
    }

    // 3. Fallback check keywords in matched rules
    const matchesKeyword = yaraMatches.some((m) =>
      vector.fallbackPatterns.some((k) => m.rule_name.toLowerCase().includes(k))
    )
    if (matchesKeyword) {
      return { detected: true, confidence: 70, evidence: ['YARA heuristic indicator matches'] }
    }

    return { detected: false, confidence: 0, evidence: [] }
  }

  return (
    <div className="space-y-4 font-mono select-none">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {FRAUD_VECTORS.map((vector) => {
          const { detected, confidence, evidence } = checkDetection(vector)
          const isExpanded = expandedVector === vector.id

          return (
            <GlassPanel
              key={vector.id}
              onClick={() => {
                if (detected) setExpandedVector(isExpanded ? null : vector.id)
              }}
              className={`p-4 border transition-all duration-300 ${
                detected
                  ? 'border-error/20 bg-error/5 cursor-pointer shadow-glow-error/10'
                  : 'border-border bg-surface/20 opacity-60'
              }`}
            >
              <div className="flex justify-between items-start gap-2 mb-2">
                <div className="flex items-center gap-2">
                  <span className={`material-symbols-outlined text-sm ${detected ? 'text-error animate-pulse' : 'text-on-surface-variant'}`}>
                    {vector.icon}
                  </span>
                  <span className="text-xs font-semibold text-on-surface">{vector.name}</span>
                </div>
                {detected ? (
                  <span className="text-[10px] font-bold text-error px-1.5 py-0.5 rounded border border-error/20 bg-error/10 animate-pulse-slow">
                    {confidence}% CONF
                  </span>
                ) : (
                  <span className="text-[9px] text-success/70 font-semibold uppercase">
                    CLEAN
                  </span>
                )}
              </div>

              <p className="text-[10px] text-on-surface-variant leading-normal mb-2">
                {vector.description}
              </p>

              {detected && (
                <div className="flex items-center gap-1 text-[9px] text-error font-semibold mt-1">
                  <span className="material-symbols-outlined text-[10px]">
                    {isExpanded ? 'keyboard_arrow_up' : 'keyboard_arrow_down'}
                  </span>
                  {isExpanded ? 'COLLAPSE EVIDENCE' : 'VIEW EVIDENTIARY TRACES'}
                </div>
              )}

              {/* Expanded Evidence trace */}
              {detected && isExpanded && (
                <div className="mt-3 p-2 border border-error/10 bg-error/5 rounded text-[9px] text-on-surface-variant max-h-[100px] overflow-y-auto space-y-1 font-mono">
                  {evidence.map((ev: string, idx: number) => (
                    <div key={idx} className="truncate select-text">
                      &gt; {ev}
                    </div>
                  ))}
                </div>
              )}
            </GlassPanel>
          )
        })}
      </div>
    </div>
  )
}
export default BehaviorMatrix
