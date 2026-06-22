import React, { useState, useEffect } from 'react'

interface GraphNode {
  id: string
  label: string
  type: 'function' | 'class' | 'permission' | 'url' | 'domain' | 'threat' | 'fraud' | 'risk'
  x: number
  y: number
  size: number
  metadata?: any
}

interface GraphEdge {
  id: string
  source: string
  target: string
  label: string
}

interface Props {
  evidenceId?: string
  analysisResult?: any
  onNodeSelect: (nodeId: string | null) => void
  selectedNode: string | null
}

const EvidenceGraph: React.FC<Props> = ({ evidenceId, analysisResult, onNodeSelect, selectedNode }) => {
  const [nodes, setNodes] = useState<GraphNode[]>([])
  const [edges, setEdges] = useState<GraphEdge[]>([])

  useEffect(() => {
    if (!analysisResult) {
      setNodes([])
      setEdges([])
      return
    }

    buildRealGraph()
  }, [evidenceId, analysisResult])

  const buildRealGraph = () => {
    const realNodes: GraphNode[] = []
    const realEdges: GraphEdge[] = []
    let nodeCounter = 0

    const genId = () => `n${++nodeCounter}`

    const appId = genId()
    realNodes.push({
      id: appId,
      label: analysisResult.apk_analysis?.app_name || 'App',
      type: 'class',
      x: 200,
      y: 300,
      size: 60
    })

    // Add permissions
    if (analysisResult.apk_analysis?.permissions) {
      const dangerous = analysisResult.apk_analysis.permissions
        .filter((p: any) => p.category === 'dangerous' || p.category === 'system')
        .slice(0, 3)
      
      dangerous.forEach((perm: any, idx: number) => {
        const permId = genId()
        const shortName = perm.name.split('.').pop() || perm.name
        realNodes.push({
          id: permId,
          label: shortName,
          type: 'permission',
          x: 100,
          y: 150 + idx * 100,
          size: 40,
          metadata: perm
        })
        realEdges.push({
          id: `e-perm-${idx}`,
          source: permId,
          target: appId,
          label: 'grants'
        })
      })
    }

    // Add suspicious functions
    if (analysisResult.top_suspicious_functions) {
      analysisResult.top_suspicious_functions.slice(0, 3).forEach((func: any, idx: number) => {
        const funcId = genId()
        const funcName = func.function_name || func.name || `func_${idx}`
        realNodes.push({
          id: funcId,
          label: funcName.length > 20 ? funcName.substring(0, 18) + '...' : funcName,
          type: 'function',
          x: 400,
          y: 200 + idx * 80,
          size: 50,
          metadata: func
        })
        realEdges.push({
          id: `e-func-${idx}`,
          source: appId,
          target: funcId,
          label: 'contains'
        })
      })
    }

    // Add network indicators
    const urlRegex = /https?:\/\/[^\s]+/g
    let urls: string[] = []
    if (analysisResult.ghidra_analysis?.suspicious_strings) {
      urls = analysisResult.ghidra_analysis.suspicious_strings
        .filter((s: string) => urlRegex.test(s))
        .slice(0, 2)
    }

    urls.forEach((url, idx) => {
      const urlId = genId()
      const domain = new URL(url).hostname
      realNodes.push({
        id: urlId,
        label: domain,
        type: 'domain',
        x: 650,
        y: 250 + idx * 100,
        size: 55,
        metadata: { url }
      })
      // Find function that might use this URL
      const lastFuncNode = realNodes.filter(n => n.type === 'function').slice(-1)[0]
      if (lastFuncNode) {
        realEdges.push({
          id: `e-url-${idx}`,
          source: lastFuncNode.id,
          target: urlId,
          label: 'connects'
        })
      }
    })

    // Add threat node
    if (analysisResult.threat_classification) {
      const threatId = genId()
      realNodes.push({
        id: threatId,
        label: analysisResult.threat_classification.threat_type || 'Threat',
        type: 'threat',
        x: 800,
        y: 300,
        size: 70,
        metadata: analysisResult.threat_classification
      })
      // Connect from domains/functions
      const connectable = realNodes.filter(n => n.type === 'domain' || n.type === 'function').slice(-2)
      connectable.forEach((node, idx) => {
        realEdges.push({
          id: `e-threat-${idx}`,
          source: node.id,
          target: threatId,
          label: 'indicates'
        })
      })
    }

    // Add fraud intent node
    if (analysisResult.fraud_intent) {
      const fraudId = genId()
      realNodes.push({
        id: fraudId,
        label: 'Fraud Intent',
        type: 'fraud',
        x: 600,
        y: 450,
        size: 75,
        metadata: analysisResult.fraud_intent
      })
      // Connect from threat or functions
      const threatNode = realNodes.find(n => n.type === 'threat')
      if (threatNode) {
        realEdges.push({
          id: 'e-fraud',
          source: threatNode.id,
          target: fraudId,
          label: 'supports'
        })
      }
    }

    // Add risk node
    const riskScore = analysisResult.threat_assessment?.risk_score || 
                     analysisResult.risk_assessment?.risk_score || 0
    if (riskScore > 0) {
      const riskId = genId()
      realNodes.push({
        id: riskId,
        label: `Risk ${riskScore}`,
        type: 'risk',
        x: 350,
        y: 500,
        size: 65,
        metadata: { score: riskScore }
      })
      // Connect from fraud/threat
      const fraudNode = realNodes.find(n => n.type === 'fraud')
      const threatNode = realNodes.find(n => n.type === 'threat')
      if (fraudNode) {
        realEdges.push({
          id: 'e-risk-fraud',
          source: fraudNode.id,
          target: riskId,
          label: 'contributes'
        })
      } else if (threatNode) {
        realEdges.push({
          id: 'e-risk-threat',
          source: threatNode.id,
          target: riskId,
          label: 'contributes'
        })
      }
    }

    setNodes(realNodes)
    setEdges(realEdges)
  }

  const getNodeColor = (type: GraphNode['type']) => {
    switch (type) {
      case 'function': return '#06b6d4'
      case 'class': return '#8b5cf6'
      case 'permission': return '#10b981'
      case 'url':
      case 'domain': return '#f59e0b'
      case 'threat': return '#ef4444'
      case 'fraud': return '#ec4899'
      case 'risk': return '#f97316'
    }
  }

  return (
    <div className="flex-1 relative overflow-hidden bg-[radial-gradient(ellipse_at_center,_rgba(139,92,246,0.05)_0%,_transparent_70%)]">
      {/* Grid Background */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none opacity-20">
        <defs>
          <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#ffffff" strokeWidth="0.5" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)" />
      </svg>

      {/* Graph Content */}
      <svg className="absolute inset-0 w-full h-full">
        {/* Draw Edges */}
        {edges.map((edge) => {
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
                stroke="rgba(255,255,255,0.15)"
                strokeWidth="2"
                className="transition-all duration-500 hover:stroke-cyan-400/50"
              />
              <text
                x={(source.x + target.x) / 2}
                y={(source.y + target.y) / 2}
                fill="rgba(255,255,255,0.4)"
                fontSize="10"
                textAnchor="middle"
                className="font-mono"
              >
                {edge.label}
              </text>
            </g>
          )
        })}

        {/* Draw Nodes */}
        {nodes.map((node) => {
          const color = getNodeColor(node.type)
          const isSelected = selectedNode === node.id
          return (
            <g
              key={node.id}
              onClick={() => onNodeSelect(isSelected ? null : node.id)}
              className="cursor-pointer"
            >
              <circle
                cx={node.x}
                cy={node.y}
                r={node.size / 2}
                fill={`${color}20`}
                stroke={color}
                strokeWidth={isSelected ? 4 : 2}
                className={`transition-all duration-300 hover:scale-110 ${isSelected ? 'filter drop-shadow-[0_0_20px_rgba(6,182,212,0.8)]' : ''}`}
              />
              <text
                x={node.x}
                y={node.y}
                textAnchor="middle"
                dominantBaseline="middle"
                fill="white"
                fontSize="11"
                fontWeight="600"
                className="font-mono pointer-events-none"
              >
                {node.label.length > 12 ? `${node.label.slice(0,10)}...` : node.label}
              </text>
            </g>
          )
        })}
      </svg>

      {nodes.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center text-xs font-mono text-on-surface-variant">
          No Data Available
        </div>
      )}

      {/* Selected Node Details */}
      {selectedNode && (
        <div className="absolute bottom-4 right-4 w-64 bg-surface-container border border-white/10 rounded-lg p-4 shadow-2xl">
          <h3 className="font-mono text-xs text-cyan-400 uppercase tracking-wider mb-2">
            Selected Evidence
          </h3>
          <p className="text-sm text-white mb-1">
            {nodes.find(n => n.id === selectedNode)?.label}
          </p>
          <p className="text-xs text-on-surface-variant">
            Click the AI Investigator panel to analyze.
          </p>
        </div>
      )}
    </div>
  )
}

export default EvidenceGraph
