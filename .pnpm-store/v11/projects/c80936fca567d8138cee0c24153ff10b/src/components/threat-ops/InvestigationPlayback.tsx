/**
 * INVESTIGATION PLAYBACK
 * Replay entire investigation for demonstrations
 */

import React, { useState, useEffect } from 'react'
import { Evidence } from '../../services/caseApi'

interface Props {
  evidence: Evidence
  analysisResult: any
  onExit: () => void
}

const InvestigationPlayback: React.FC<Props> = ({ evidence, analysisResult, onExit }) => {
  const [currentStep, setCurrentStep] = useState(0)
  const [isPlaying, setIsPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)

  const steps = [
    { title: 'APK Upload', description: evidence.original_filename, icon: 'upload' },
    { title: 'Manifest Analysis', description: `${(analysisResult.apk_analysis?.permissions || []).length} permissions found`, icon: 'description' },
    { title: 'DEX Extraction', description: 'Classes and methods indexed', icon: 'inventory_2' },
    { title: 'Function Discovery', description: `${(analysisResult.suspicious_functions || []).length} functions analyzed`, icon: 'functions' },
    { title: 'Threat Classification', description: analysisResult.threat_classification?.threat_type || 'Threat detected', icon: 'security' },
    { title: 'Fraud Analysis', description: `${(analysisResult.fraud_intent?.objectives || []).length} fraud objectives`, icon: 'gavel' },
    { title: 'Risk Scoring', description: `Risk: ${analysisResult.threat_assessment?.risk_score || analysisResult.risk_assessment?.risk_score || 0}/100`, icon: 'speed' },
    { title: 'Report Generation', description: 'Investigation complete', icon: 'task_alt' }
  ]

  useEffect(() => {
    if (isPlaying && currentStep < steps.length - 1) {
      const timer = setTimeout(() => {
        setCurrentStep(currentStep + 1)
      }, 2000 / speed)
      return () => clearTimeout(timer)
    } else if (currentStep >= steps.length - 1) {
      setIsPlaying(false)
    }
  }, [isPlaying, currentStep, speed])

  return (
    <div className="h-full flex flex-col bg-[#0a0a0f]">
      {/* Playback Controls */}
      <div className="h-16 bg-[#1a1f2e] border-b border-cyan-900/30 flex items-center justify-between px-6">
        <div className="flex items-center gap-4">
          <button
            onClick={onExit}
            className="px-3 py-1.5 bg-[#0f1419] border border-cyan-900/30 hover:border-cyan-700 rounded text-xs font-mono text-gray-400"
          >
            <span className="material-symbols-outlined text-sm mr-1 align-middle">arrow_back</span>
            Exit Playback
          </button>
          
          <div className="h-8 w-px bg-cyan-900/30"></div>
          
          <div className="font-mono text-sm text-cyan-400">
            Investigation Playback
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
            className="px-2 py-1 bg-[#0f1419] border border-cyan-900/30 hover:border-cyan-700 rounded"
          >
            <span className="material-symbols-outlined text-sm">skip_previous</span>
          </button>
          
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="px-3 py-1.5 bg-cyan-500/20 border border-cyan-500/50 hover:bg-cyan-500/30 rounded"
          >
            <span className="material-symbols-outlined text-sm">
              {isPlaying ? 'pause' : 'play_arrow'}
            </span>
          </button>
          
          <button
            onClick={() => setCurrentStep(Math.min(steps.length - 1, currentStep + 1))}
            className="px-2 py-1 bg-[#0f1419] border border-cyan-900/30 hover:border-cyan-700 rounded"
          >
            <span className="material-symbols-outlined text-sm">skip_next</span>
          </button>

          <select
            value={speed}
            onChange={(e) => setSpeed(Number(e.target.value))}
            className="px-2 py-1 bg-[#0f1419] border border-cyan-900/30 text-xs font-mono rounded focus:outline-none focus:border-cyan-500"
          >
            <option value="0.5">0.5x</option>
            <option value="1">1x</option>
            <option value="2">2x</option>
            <option value="4">4x</option>
          </select>

          <div className="text-xs font-mono text-gray-600">
            {currentStep + 1} / {steps.length}
          </div>
        </div>
      </div>

      {/* Playback Visualization */}
      <div className="flex-1 flex items-center justify-center p-12">
        <div className="max-w-4xl w-full">
          {/* Progress Bar */}
          <div className="mb-12">
            <div className="h-1 bg-[#1a1f2e] rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-500"
                style={{ width: `${((currentStep + 1) / steps.length) * 100}%` }}
              ></div>
            </div>
          </div>

          {/* Current Step */}
          <div className="text-center mb-8">
            <div className="w-32 h-32 mx-auto mb-6 relative">
              <div className="absolute inset-0 border-4 border-cyan-500/20 rounded-full animate-pulse"></div>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="material-symbols-outlined text-6xl text-cyan-400">
                  {steps[currentStep].icon}
                </span>
              </div>
            </div>
            
            <h2 className="text-2xl font-mono text-white mb-3">
              {steps[currentStep].title}
            </h2>
            
            <p className="text-lg text-gray-400 font-mono">
              {steps[currentStep].description}
            </p>
          </div>

          {/* Timeline */}
          <div className="flex justify-between items-center mt-12">
            {steps.map((step, idx) => (
              <div
                key={idx}
                className={`flex flex-col items-center flex-1 transition-opacity ${
                  idx <= currentStep ? 'opacity-100' : 'opacity-30'
                }`}
              >
                <div
                  className={`w-10 h-10 rounded-full flex items-center justify-center mb-2 transition-colors ${
                    idx === currentStep
                      ? 'bg-cyan-500 border-2 border-cyan-300'
                      : idx < currentStep
                      ? 'bg-green-500'
                      : 'bg-[#1a1f2e] border border-cyan-900/30'
                  }`}
                >
                  <span className="material-symbols-outlined text-sm text-white">
                    {idx < currentStep ? 'check' : step.icon}
                  </span>
                </div>
                <div className="text-[10px] font-mono text-gray-600 text-center max-w-[80px]">
                  {step.title}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export default InvestigationPlayback
