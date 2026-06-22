/**
 * APK DISSECTION GRAPH - LIVE INTELLIGENCE ENGINE
 * Maltego-like malware intelligence map that auto-generates from real APK artifacts
 * 
 * BEHAVIOR:
 * - Auto-generates complete graph on load
 * - Progressive node revelation from available APK analysis artifacts
 * - Deep interconnection between evidence
 * - Click-through investigation flow: APK → Manifest → Permissions → Functions → Behaviors → Threats → Verdict
 */

import React, { useState, useEffect, useRef } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { Evidence } from '../../services/caseApi'

interface GraphNode {
  id: string
  label: string
  type: 'root' | 'manifest' | 'permission' | 'activity' | 'service' | 'receiver' | 'provider' | 'certificate' | 'resource' | 'dex' | 'string' | 'url' | 'domain' | 'library' | 'class' | 'method' | 'function' | 'import' | 'suspicious_function' | 'behavior' | 'threat' | 'fraud' | 'risk' | 'ioc' | 'attack_chain' | 'verdict'
  x: number
  y: number
  size: number
  metadata?: any
  layer: number
  parent?: string
  revealed: boolean
}

interface GraphEdge {
  id: string
  source: string
  target: string
  label: string
  type?: 'evidence' | 'correlation' | 'contribution' | 'dependency'
}

interface Props {
  evidence: Evidence
  analysisResult: any
  onNodeSelect: (node: any) => void
  selectedNode: any
}

const APKDissectionGraph: React.FC<Props> = ({ evidence, analysisResult, onNodeSelect, selectedNode }) => {
  const [nodes, setNodes] = useState<GraphNode[]>([])
  const [edges, setEdges] = useState<GraphEdge[]>([])
  const [revealedLayers, setRevealedLayers] = useState<Set<number>>(new Set([0]))
  const [autoReveal, setAutoReveal] = useState(true)
  const svgRef = useRef<SVGSVGElement>(null)
  const [viewBox] = useState({ x: 0, y: 0, width: 1200, height: 800 })
  const navigate = useNavigate()
  const { caseId } = useParams()

  const handleLaunchDynamicAnalysis = () => {
    // Navigate to Device Lab with case and APK context
    const apkName = evidence.original_filename
    navigate(`/device-lab/${caseId}?apk=${encodeURIComponent(apkName)}`)
  }

  // AUTO-GENERATE COMPLETE GRAPH ON LOAD
  useEffect(() => {
    if (!analysisResult) return
    buildCompleteIntelligenceGraph()
  }, [evidence, analysisResult])

  // PROGRESSIVE REVELATION
  useEffect(() => {
    if (!autoReveal || nodes.length === 0) return

    const maxLayer = Math.max(...nodes.map(n => n.layer))
    const currentMaxRevealed = Math.max(...Array.from(revealedLayers))

    if (currentMaxRevealed < maxLayer) {
      const timer = setTimeout(() => {
        setRevealedLayers(prev => new Set([...prev, currentMaxRevealed + 1]))
      }, 800) // Reveal next layer every 800ms
      return () => clearTimeout(timer)
    } else {
      setAutoReveal(false) // Stop auto-reveal once complete
    }
  }, [revealedLayers, nodes, autoReveal])

  const buildCompleteIntelligenceGraph = () => {
    const allNodes: GraphNode[] = []
    const allEdges: GraphEdge[] = []
    let nodeId = 0
    const genId = () => `n${++nodeId}`

    // Positioning helpers
    const centerX = 600
    const centerY = 400
    const layerSpacing = 180
    
    // ============================================================================
    // LAYER 0: ROOT (APK)
    // ============================================================================
    const rootId = genId()
    const appName = analysisResult.apk_analysis?.app_name || 
                   analysisResult.apk_analysis?.package_name || 
                   evidence.original_filename

    allNodes.push({
      id: rootId,
      label: appName,
      type: 'root',
      x: centerX,
      y: centerY,
      size: 90,
      layer: 0,
      revealed: true,
      metadata: {
        filename: evidence.original_filename,
        package: analysisResult.apk_analysis?.package_name,
        sha256: evidence.sha256,
        version: analysisResult.apk_analysis?.version_name
      }
    })

    // ============================================================================
    // LAYER 1: APK STRUCTURE
    // ============================================================================
    const layer1Radius = layerSpacing
    const layer1Items: Array<{id: string, label: string, type: any, count: number, data: any}> = []

    // Manifest
    if (analysisResult.apk_analysis?.manifest) {
      const manifestId = genId()
      layer1Items.push({
        id: manifestId,
        label: 'Manifest',
        type: 'manifest',
        count: 1,
        data: analysisResult.apk_analysis.manifest
      })
    }

    // Permissions
    const permissions = analysisResult.apk_analysis?.permissions || []
    if (permissions.length > 0) {
      const permId = genId()
      layer1Items.push({
        id: permId,
        label: `Permissions (${permissions.length})`,
        type: 'permission',
        count: permissions.length,
        data: permissions
      })
    }

    // Activities
    const activities = analysisResult.apk_analysis?.activities || []
    if (activities.length > 0) {
      const actId = genId()
      layer1Items.push({
        id: actId,
        label: `Activities (${activities.length})`,
        type: 'activity',
        count: activities.length,
        data: activities
      })
    }

    // Services
    const services = analysisResult.apk_analysis?.services || []
    if (services.length > 0) {
      const svcId = genId()
      layer1Items.push({
        id: svcId,
        label: `Services (${services.length})`,
        type: 'service',
        count: services.length,
        data: services
      })
    }

    // DEX Files
    const dexFiles = analysisResult.apk_analysis?.files?.dex_files || []
    if (dexFiles.length > 0) {
      const dexId = genId()
      layer1Items.push({
        id: dexId,
        label: `DEX (${dexFiles.length})`,
        type: 'dex',
        count: dexFiles.length,
        data: dexFiles
      })
    }

    // URLs/Domains
    const urls = analysisResult.apk_analysis?.urls || []
    const domains = analysisResult.apk_analysis?.domains || []
    if (urls.length + domains.length > 0) {
      const netId = genId()
      layer1Items.push({
        id: netId,
        label: `Network (${urls.length + domains.length})`,
        type: 'url',
        count: urls.length + domains.length,
        data: { urls, domains }
      })
    }

    // Native Libraries
    const libraries = analysisResult.apk_analysis?.native_libraries || []
    if (libraries.length > 0) {
      const libId = genId()
      layer1Items.push({
        id: libId,
        label: `Libraries (${libraries.length})`,
        type: 'library',
        count: libraries.length,
        data: libraries
      })
    }

    // Certificates
    if (analysisResult.apk_analysis?.certificates) {
      const certId = genId()
      layer1Items.push({
        id: certId,
        label: 'Certificates',
        type: 'certificate',
        count: 1,
        data: analysisResult.apk_analysis.certificates
      })
    }

    // Position Layer 1 nodes in circle around root
    const angleStep = (2 * Math.PI) / layer1Items.length
    layer1Items.forEach((item, idx) => {
      const angle = angleStep * idx
      const x = centerX + Math.cos(angle) * layer1Radius
      const y = centerY + Math.sin(angle) * layer1Radius

      allNodes.push({
        id: item.id,
        label: item.label,
        type: item.type,
        x,
        y,
        size: 60,
        layer: 1,
        parent: rootId,
        revealed: false,
        metadata: item.data
      })

      allEdges.push({
        id: `e_${rootId}_${item.id}`,
        source: rootId,
        target: item.id,
        label: 'contains',
        type: 'evidence'
      })
    })

    // ============================================================================
    // LAYER 2: SUSPICIOUS FUNCTIONS
    // ============================================================================
    const suspiciousFuncs = analysisResult.suspicious_functions || analysisResult.top_suspicious_functions || []
    const layer2Radius = layer1Radius + layerSpacing
    
    if (suspiciousFuncs.length > 0) {
      const funcAngleStep = (2 * Math.PI) / Math.min(suspiciousFuncs.length, 12)
      
      suspiciousFuncs.slice(0, 12).forEach((func: any, idx: number) => {
        const funcId = genId()
        const angle = funcAngleStep * idx + Math.PI / 4
        const x = centerX + Math.cos(angle) * layer2Radius
        const y = centerY + Math.sin(angle) * layer2Radius

        const funcName = func.function_name || func.method_name || func.name || `func_${idx}`
        const shortName = funcName.length > 20 ? '...' + funcName.slice(-17) : funcName

        allNodes.push({
          id: funcId,
          label: shortName,
          type: 'suspicious_function',
          x,
          y,
          size: 50,
          layer: 2,
          revealed: false,
          metadata: func
        })

        // Connect to DEX node if exists
        const dexNode = allNodes.find(n => n.type === 'dex')
        if (dexNode) {
          allEdges.push({
            id: `e_${dexNode.id}_${funcId}`,
            source: dexNode.id,
            target: funcId,
            label: 'contains',
            type: 'evidence'
          })
        }
      })
    }

    // ============================================================================
    // LAYER 3: BEHAVIORS
    // ============================================================================
    const behaviors: Array<{type: string, label: string, evidence: string[]}> = []

    // Detect behaviors from functions
    const behaviorPatterns = {
      'credential_collection': ['password', 'credential', 'login', 'account'],
      'accessibility_abuse': ['accessibility', 'AccessibilityService'],
      'overlay': ['overlay', 'TYPE_SYSTEM_ALERT', 'WindowManager'],
      'sms': ['sms', 'SMS_RECEIVED', 'SmsManager'],
      'reflection': ['reflection', 'Class.forName', 'invoke'],
      'crypto': ['encrypt', 'decrypt', 'cipher', 'AES'],
      'network': ['http', 'socket', 'URL', 'download']
    }

    Object.entries(behaviorPatterns).forEach(([behaviorType, patterns]) => {
      const matchingFuncs = suspiciousFuncs.filter((f: any) => {
        const funcStr = JSON.stringify(f).toLowerCase()
        return patterns.some(p => funcStr.includes(p.toLowerCase()))
      })

      if (matchingFuncs.length > 0) {
        behaviors.push({
          type: behaviorType,
          label: behaviorType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
          evidence: matchingFuncs.map((f: any) => f.function_name || f.name).slice(0, 3)
        })
      }
    })

    const layer3Radius = layer2Radius + layerSpacing
    const behaviorAngleStep = (2 * Math.PI) / Math.max(behaviors.length, 1)

    behaviors.forEach((behavior, idx) => {
      const behaviorId = genId()
      const angle = behaviorAngleStep * idx
      const x = centerX + Math.cos(angle) * layer3Radius
      const y = centerY + Math.sin(angle) * layer3Radius

      allNodes.push({
        id: behaviorId,
        label: behavior.label,
        type: 'behavior',
        x,
        y,
        size: 65,
        layer: 3,
        revealed: false,
        metadata: { evidence: behavior.evidence, type: behavior.type }
      })

      // Connect to related functions
      behavior.evidence.forEach(funcName => {
        const funcNode = allNodes.find(n => 
          n.type === 'suspicious_function' && 
          n.metadata?.function_name?.includes(funcName)
        )
        if (funcNode) {
          allEdges.push({
            id: `e_${funcNode.id}_${behaviorId}`,
            source: funcNode.id,
            target: behaviorId,
            label: 'exhibits',
            type: 'correlation'
          })
        }
      })
    })

    // ============================================================================
    // LAYER 4: THREATS & FRAUD
    // ============================================================================
    const layer4Radius = layer3Radius + layerSpacing

    // Threat Classification
    if (analysisResult.threat_classification) {
      const threatId = genId()
      const threat = analysisResult.threat_classification
      
      allNodes.push({
        id: threatId,
        label: threat.threat_type || threat.threat_family || 'Threat',
        type: 'threat',
        x: centerX - 150,
        y: centerY + layer4Radius - centerY,
        size: 75,
        layer: 4,
        revealed: false,
        metadata: threat
      })

      // Connect to behaviors
      behaviors.slice(0, 2).forEach(behavior => {
        const behaviorNode = allNodes.find(n => n.metadata?.type === behavior.type)
        if (behaviorNode) {
          allEdges.push({
            id: `e_${behaviorNode.id}_${threatId}`,
            source: behaviorNode.id,
            target: threatId,
            label: 'indicates',
            type: 'correlation'
          })
        }
      })
    }

    // Fraud Intent
    if (analysisResult.fraud_intent?.objectives?.length > 0) {
      const fraudId = genId()
      
      allNodes.push({
        id: fraudId,
        label: 'Fraud Intent',
        type: 'fraud',
        x: centerX + 150,
        y: centerY + layer4Radius - centerY,
        size: 75,
        layer: 4,
        revealed: false,
        metadata: analysisResult.fraud_intent
      })

      // Connect to threat
      const threatNode = allNodes.find(n => n.type === 'threat')
      if (threatNode) {
        allEdges.push({
          id: `e_${threatNode.id}_${fraudId}`,
          source: threatNode.id,
          target: fraudId,
          label: 'supports',
          type: 'correlation'
        })
      }
    }

    // ============================================================================
    // LAYER 5: RISK & VERDICT
    // ============================================================================
    const riskScore = analysisResult.threat_assessment?.risk_score || analysisResult.risk_assessment?.risk_score || 0
    
    if (riskScore > 0) {
      const riskId = genId()
      
      allNodes.push({
        id: riskId,
        label: `Risk: ${riskScore}`,
        type: 'risk',
        x: centerX,
        y: centerY - layer4Radius + centerY - 100,
        size: 70,
        layer: 5,
        revealed: false,
        metadata: analysisResult.threat_assessment || analysisResult.risk_assessment
      })

      // Connect from threat and fraud
      const threatNode = allNodes.find(n => n.type === 'threat')
      const fraudNode = allNodes.find(n => n.type === 'fraud')
      
      if (threatNode) {
        allEdges.push({
          id: `e_${threatNode.id}_${riskId}`,
          source: threatNode.id,
          target: riskId,
          label: 'contributes',
          type: 'contribution'
        })
      }
      if (fraudNode) {
        allEdges.push({
          id: `e_${fraudNode.id}_${riskId}`,
          source: fraudNode.id,
          target: riskId,
          label: 'contributes',
          type: 'contribution'
        })
      }
    }

    // Final Verdict
    const severity = analysisResult.threat_assessment?.severity || analysisResult.risk_assessment?.severity
    if (severity) {
      const verdictId = genId()
      
      allNodes.push({
        id: verdictId,
        label: `Verdict: ${severity}`,
        type: 'verdict',
        x: centerX,
        y: 100,
        size: 80,
        layer: 6,
        revealed: false,
        metadata: {
          severity,
          riskScore,
          summary: analysisResult.threat_assessment?.summary || analysisResult.risk_assessment?.summary
        }
      })

      // Connect from risk
      const riskNode = allNodes.find(n => n.type === 'risk')
      if (riskNode) {
        allEdges.push({
          id: `e_${riskNode.id}_${verdictId}`,
          source: riskNode.id,
          target: verdictId,
          label: 'determines',
          type: 'dependency'
        })
      }
    }

    setNodes(allNodes)
    setEdges(allEdges)
  }

  const handleNodeClick = (node: GraphNode) => {
    onNodeSelect(node)
  }

  const getNodeColor = (type: string) => {
    const colors: Record<string, string> = {
      root: '#06b6d4',
      manifest: '#8b5cf6',
      permission: '#10b981',
      activity: '#f59e0b',
      service: '#f97316',
      receiver: '#ef4444',
      provider: '#ec4899',
      certificate: '#6b7280',
      resource: '#64748b',
      dex: '#6366f1',
      string: '#64748b',
      url: '#f59e0b',
      domain: '#fb923c',
      library: '#475569',
      class: '#6366f1',
      method: '#0ea5e9',
      function: '#0ea5e9',
      import: '#64748b',
      suspicious_function: '#ef4444',
      behavior: '#db2777',
      threat: '#dc2626',
      fraud: '#ec4899',
      risk: '#ea580c',
      ioc: '#f97316',
      attack_chain: '#dc2626',
      verdict: '#7c3aed'
    }
    return colors[type] || '#64748b'
  }

  const getEdgeColor = (type?: string) => {
    switch (type) {
      case 'evidence': return 'rgba(6, 182, 212, 0.3)'
      case 'correlation': return 'rgba(239, 68, 68, 0.4)'
      case 'contribution': return 'rgba(234, 88, 12, 0.5)'
      case 'dependency': return 'rgba(124, 58, 237, 0.4)'
      default: return 'rgba(156, 163, 175, 0.2)'
    }
  }

  const visibleNodes = nodes.filter(n => revealedLayers.has(n.layer))
  const visibleEdges = edges.filter(e => {
    const source = nodes.find(n => n.id === e.source)
    const target = nodes.find(n => n.id === e.target)
    return source && target && revealedLayers.has(source.layer) && revealedLayers.has(target.layer)
  })

  return (
    <div className="h-full bg-[#0f1419] border border-cyan-900/30 rounded flex flex-col overflow-hidden relative">
      {/* Header */}
      <div className="h-10 bg-[#1a1f2e] border-b border-cyan-900/30 flex items-center justify-between px-4">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-sm text-cyan-400">account_tree</span>
          <span className="font-mono text-xs uppercase tracking-wider text-gray-400">
            Malware Intelligence Map
          </span>
          <span className="text-[10px] font-mono text-gray-600">
            ({visibleNodes.length}/{nodes.length} nodes revealed)
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleLaunchDynamicAnalysis}
            className="px-3 py-1 text-xs font-mono bg-green-500/20 border border-green-500/50 hover:bg-green-500/30 rounded text-green-400 flex items-center gap-1.5 transition-colors"
          >
            <span className="material-symbols-outlined text-sm">smartphone</span>
            Launch Dynamic Analysis
          </button>
          <button
            onClick={() => {
              setRevealedLayers(new Set([0, 1, 2, 3, 4, 5, 6]))
              setAutoReveal(false)
            }}
            className="px-2 py-0.5 text-[10px] font-mono bg-cyan-500/20 border border-cyan-500/50 hover:bg-cyan-500/30 rounded text-cyan-400"
          >
            Reveal All
          </button>
        </div>
      </div>

      {/* Graph Canvas */}
      <div className="flex-1 relative overflow-hidden bg-[radial-gradient(ellipse_at_center,_rgba(6,182,212,0.03)_0%,_transparent_70%)]">
        <svg ref={svgRef} className="w-full h-full" viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.width} ${viewBox.height}`}>
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(6,182,212,0.05)" strokeWidth="0.5" />
            </pattern>
            <filter id="glow">
              <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
              <feMerge>
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>
          
          <rect width="100%" height="100%" fill="url(#grid)" />
          
          {/* Edges */}
          <g>
            {visibleEdges.map((edge) => {
              const source = nodes.find(n => n.id === edge.source)
              const target = nodes.find(n => n.id === edge.target)
              if (!source || !target) return null

              return (
                <g key={edge.id}>
                  <line
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                    stroke={getEdgeColor(edge.type)}
                    strokeWidth="2"
                    className="transition-all duration-500"
                  />
                  <text
                    x={(source.x + target.x) / 2}
                    y={(source.y + target.y) / 2}
                    fill="rgba(156, 163, 175, 0.4)"
                    fontSize="8"
                    textAnchor="middle"
                    className="font-mono pointer-events-none"
                  >
                    {edge.label}
                  </text>
                </g>
              )
            })}
          </g>

          {/* Nodes */}
          <g>
            {visibleNodes.map((node) => {
              const color = getNodeColor(node.type)
              const isSelected = selectedNode?.id === node.id

              return (
                <g
                  key={node.id}
                  onClick={() => handleNodeClick(node)}
                  className="cursor-pointer"
                  style={{ 
                    animation: 'fadeIn 0.5s ease-out',
                    transformOrigin: `${node.x}px ${node.y}px`
                  }}
                >
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={node.size / 2}
                    fill={`${color}20`}
                    stroke={color}
                    strokeWidth={isSelected ? 4 : 2}
                    filter={isSelected ? 'url(#glow)' : undefined}
                    className="transition-all duration-300 hover:opacity-80"
                  />
                  <text
                    x={node.x}
                    y={node.y}
                    textAnchor="middle"
                    dominantBaseline="middle"
                    fill="white"
                    fontSize={node.type === 'root' ? '13' : node.type === 'verdict' ? '11' : '9'}
                    fontWeight={['root', 'verdict', 'threat'].includes(node.type) ? '600' : '500'}
                    className="font-mono pointer-events-none"
                  >
                    {node.label}
                  </text>
                </g>
              )
            })}
          </g>
        </svg>

        {/* Legend */}
        <div className="absolute bottom-4 left-4 bg-[#1a1f2e]/95 border border-cyan-900/30 rounded p-3 backdrop-blur text-[10px] font-mono">
          <div className="text-cyan-400 mb-2 uppercase">Live Intelligence Map</div>
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-cyan-500/30 border border-cyan-500"></div>
              <span className="text-gray-400">Structure</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500/30 border border-red-500"></div>
              <span className="text-gray-400">Suspicious</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-pink-500/30 border border-pink-500"></div>
              <span className="text-gray-400">Behaviors</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-orange-500/30 border border-orange-500"></div>
              <span className="text-gray-400">Risk</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-purple-500/30 border border-purple-500"></div>
              <span className="text-gray-400">Verdict</span>
            </div>
          </div>
        </div>

        {/* Layer Info */}
        <div className="absolute top-4 right-4 bg-[#1a1f2e]/95 border border-cyan-900/30 rounded p-2 backdrop-blur text-[10px] font-mono text-gray-400">
          Layers: {revealedLayers.size}/7 revealed
        </div>
      </div>

      <style>{`
        @keyframes fadeIn {
          from {
            opacity: 0;
            transform: scale(0.8);
          }
          to {
            opacity: 1;
            transform: scale(1);
          }
        }
      `}</style>
    </div>
  )
}

export default APKDissectionGraph
