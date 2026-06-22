import React, { useState, useEffect } from 'react'
import GlassPanel from '../ui/GlassPanel'

interface GraphNode {
  id: string
  name: string
  class: string
  risk: number
  x: number
  y: number
}

interface GraphEdge {
  source: string
  target: string
}

interface ThreatGraphProps {
  callGraph: Record<string, string[]>
  suspiciousFunctions: any[]
}

export const ThreatGraph: React.FC<ThreatGraphProps> = ({ callGraph, suspiciousFunctions }) => {
  const [nodes, setNodes] = useState<GraphNode[]>([])
  const [edges, setEdges] = useState<GraphEdge[]>([])
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
  
  // Interactive Pan / Zoom state
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [zoom, setZoom] = useState(1)
  const [isDragging, setIsDragging] = useState(false)
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 })

  useEffect(() => {
    // Construct graph nodes and layout positions statically using concentric rings
    const tempNodes: GraphNode[] = []
    const tempEdges: GraphEdge[] = []
    
    // Add suspicious functions
    suspiciousFunctions.forEach((f, idx) => {
      const angle = (idx / suspiciousFunctions.length) * 2 * Math.PI
      const ringRadius = f.risk_score >= 70 ? 120 : 220
      
      tempNodes.push({
        id: f.signature || `${f.class_name}.${f.name}`,
        name: f.name,
        class: f.class_name,
        risk: f.risk_score,
        x: 400 + Math.cos(angle) * ringRadius,
        y: 300 + Math.sin(angle) * ringRadius
      })
    })

    // Connect edges based on call graph mapping
    Object.entries(callGraph).forEach(([source, targets]) => {
      targets.forEach((target) => {
        // Find if nodes exist
        const sourceNode = tempNodes.find(n => n.name === source || n.id.includes(source))
        const targetNode = tempNodes.find(n => n.name === target || n.id.includes(target))
        if (sourceNode && targetNode) {
          tempEdges.push({
            source: sourceNode.id,
            target: targetNode.id
          })
        }
      })
    })

    setNodes(tempNodes)
    setEdges(tempEdges)
  }, [callGraph, suspiciousFunctions])

  const getNodeColor = (risk: number) => {
    if (risk >= 70) return '#ff4a4a' // red
    if (risk >= 40) return '#ffb84d' // orange
    return '#4ade80' // green
  }

  // Pan handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true)
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y })
  }

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return
    setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y })
  }

  const handleMouseUp = () => {
    setIsDragging(false)
  }

  const handleZoom = (factor: number) => {
    setZoom(prev => Math.max(0.5, Math.min(3, prev * factor)))
  }

  const resetViewport = () => {
    setPan({ x: 0, y: 0 })
    setZoom(1)
    setSelectedNode(null)
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 font-mono text-xs select-none">
      
      {/* Dynamic Graph canvas */}
      <GlassPanel className="p-4 col-span-1 lg:col-span-3 border-border bg-surface-variant/5 flex flex-col h-[450px] relative overflow-hidden">
        {/* Controls Overlay */}
        <div className="absolute top-4 left-4 z-20 flex items-center gap-1.5 bg-surface/80 backdrop-blur border border-border p-1.5 rounded-lg">
          <button
            onClick={() => handleZoom(1.1)}
            className="p-1 rounded bg-surface hover:bg-surface-variant text-on-surface border border-border"
            title="Zoom In"
          >
            <span className="material-symbols-outlined text-[14px] block">zoom_in</span>
          </button>
          <button
            onClick={() => handleZoom(0.9)}
            className="p-1 rounded bg-surface hover:bg-surface-variant text-on-surface border border-border"
            title="Zoom Out"
          >
            <span className="material-symbols-outlined text-[14px] block">zoom_out</span>
          </button>
          <button
            onClick={resetViewport}
            className="p-1 rounded bg-surface hover:bg-surface-variant text-on-surface border border-border"
            title="Reset Fit"
          >
            <span className="material-symbols-outlined text-[14px] block">restart_alt</span>
          </button>
        </div>

        {/* Call Graph Canvas */}
        <div
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          className={`flex-1 h-full ${nodes.length > 0 ? 'cursor-grab active:cursor-grabbing' : ''}`}
        >
          {nodes.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-on-surface-variant/45 text-center px-6">
              <span className="material-symbols-outlined text-5xl mb-3 opacity-40">hub</span>
              <p className="uppercase tracking-[0.18em] text-[10px] font-bold">No call graph nodes available</p>
              <p className="text-[11px] mt-2 max-w-md">
                Run reverse engineering or select an artifact with stored call relationships to populate this view.
              </p>
            </div>
          ) : (
            <svg className="w-full h-full">
              <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
              
              {/* Connecting Lines */}
              {edges.map((edge, idx) => {
                const sNode = nodes.find(n => n.id === edge.source)
                const tNode = nodes.find(n => n.id === edge.target)
                if (!sNode || !tNode) return null
                return (
                  <line
                    key={idx}
                    x1={sNode.x}
                    y1={sNode.y}
                    x2={tNode.x}
                    y2={tNode.y}
                    stroke="#ffffff"
                    strokeWidth="1"
                    strokeOpacity="0.15"
                  />
                )
              })}

              {/* Node Circles */}
              {nodes.map((node) => {
                const isSelected = selectedNode?.id === node.id
                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x}, ${node.y})`}
                    className="cursor-pointer"
                    onClick={(e) => {
                      e.stopPropagation()
                      setSelectedNode(node)
                    }}
                  >
                    {/* Ring highlight if selected */}
                    {isSelected && (
                      <circle
                        r="14"
                        fill="none"
                        stroke="#ffffff"
                        strokeWidth="1.5"
                        strokeDasharray="4 2"
                        className="animate-spin"
                        style={{ animationDuration: '6s' }}
                      />
                    )}
                    {/* Inner color circle */}
                    <circle
                      r="8"
                      fill={getNodeColor(node.risk)}
                      stroke="#ffffff"
                      strokeWidth="1.5"
                      strokeOpacity={isSelected ? 1 : 0.4}
                    />
                    {/* Node text label */}
                    <text
                      dy="24"
                      textAnchor="middle"
                      className="text-[10px] font-bold pointer-events-none fill-on-surface"
                      style={{ filter: 'drop-shadow(0 1px 2px rgba(0,0,0,0.5))' }}
                    >
                      {node.name}
                    </text>
                  </g>
                )
              })}
              </g>
            </svg>
          )}
        </div>
      </GlassPanel>

      {/* Selected Node Intelligence Details */}
      <GlassPanel className="p-6 col-span-1 border-border bg-surface-variant/10 flex flex-col justify-between h-[450px]">
        {selectedNode ? (
          <div className="flex flex-col h-full space-y-4 overflow-hidden">
            <div className="border-b border-border pb-3">
              <h4 className="font-bold text-on-surface text-sm truncate">{selectedNode.name}</h4>
              <p className="text-[10px] text-on-surface-variant opacity-60 truncate">{selectedNode.class}</p>
            </div>
            
            <div className="flex-1 overflow-y-auto space-y-4 pr-1 scrollbar-thin">
              <div>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-[10px] font-bold text-on-surface-variant uppercase">Risk Contribution</span>
                  <span className="text-xs font-bold" style={{ color: getNodeColor(selectedNode.risk) }}>{selectedNode.risk}/100</span>
                </div>
                <div className="w-full bg-border rounded-full h-1.5 overflow-hidden">
                  <div 
                    className="h-full rounded-full transition-all duration-500"
                    style={{ 
                      width: `${selectedNode.risk}%`,
                      backgroundColor: getNodeColor(selectedNode.risk)
                    }}
                  />
                </div>
              </div>

              <div>
                <h5 className="text-[10px] font-bold text-primary uppercase mb-1">Relationship Context</h5>
                <div className="space-y-1">
                  <div className="flex justify-between text-[10px]">
                    <span className="text-on-surface-variant opacity-60">In-degree:</span>
                    <span className="text-on-surface">{edges.filter(e => e.target === selectedNode.id).length}</span>
                  </div>
                  <div className="flex justify-between text-[10px]">
                    <span className="text-on-surface-variant opacity-60">Out-degree:</span>
                    <span className="text-on-surface">{edges.filter(e => e.source === selectedNode.id).length}</span>
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-white/5">
                <button 
                  onClick={() => {
                    // This will be handled by the parent to switch tabs and select function
                    window.dispatchEvent(new CustomEvent('sentinel:select-function', { 
                      detail: { signature: selectedNode.id } 
                    }))
                  }}
                  className="w-full btn-primary py-2 text-[10px] font-bold flex items-center justify-center gap-1.5"
                >
                  <span className="material-symbols-outlined text-sm">find_in_page</span>
                  VIEW SOURCE & AI ANALYSIS
                </button>
              </div>
            </div>

            <div className="text-[9px] text-on-surface-variant opacity-50 bg-surface/40 p-2.5 rounded-lg border border-border mt-auto">
              Source: Reverse Engineering Pipeline (Androguard xrefs). Select a node to inspect its risk profile and code.
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-center opacity-60">
            <span className="material-symbols-outlined text-4xl mb-2">hub</span>
            <p className="text-[11px]">Select a node in the graph to view intelligence metrics.</p>
          </div>
        )}
      </GlassPanel>
    </div>
  )
}
export default ThreatGraph
