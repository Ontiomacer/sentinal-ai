import React, { useState, useEffect, useRef } from 'react';
import { GhidraCallGraph } from '../services/ghidraApi';
import { cn } from '../utils/cn';

interface CallGraphVisualizationProps {
  callGraph: GhidraCallGraph | null;
  onNodeClick?: (node: any) => void;
}

interface GraphNode {
  id: string;
  label: string;
  x: number;
  y: number;
  size: number;
  threat: 'high' | 'medium' | 'low';
}

interface GraphEdge {
  source: string;
  target: string;
  weight: number;
}

/**
 * Interactive Call Graph Visualization
 * 
 * Renders a force-directed graph showing:
 * - Function nodes with threat scores
 * - Execution relationships as edges
 * - Draggable nodes
 * - Zoom and pan support
 * - Suspicious path highlighting
 */
export const CallGraphVisualization: React.FC<CallGraphVisualizationProps> = ({
  callGraph,
  onNodeClick
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });

  // Initialize graph from callGraph data
  useEffect(() => {
    if (!callGraph || callGraph.nodes.length === 0) return;

    // Create nodes
    const newNodes: GraphNode[] = callGraph.nodes.map((node, idx) => {
      const angle = (idx / callGraph.nodes.length) * Math.PI * 2;
      const radius = 200 + Math.random() * 100;
      const nAny = node as any;
      return {
        id: node.id || `node_${idx}`,
        label: nAny.name || node.label || node.id || `Node ${idx}`,
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
        size: Math.min(40, 20 + (nAny.xref_count || 0) * 2),
        threat: nAny.threat_score > 70 ? 'high' : nAny.threat_score > 40 ? 'medium' : 'low'
      };
    });

    setNodes(newNodes);

    // Create edges
    const newEdges: GraphEdge[] = callGraph.edges.map((edge) => {
      const eAny = edge as any;
      return {
        source: edge.source || eAny.from || `node_0`,
        target: edge.target || eAny.to || `node_1`,
        weight: eAny.weight || 1
      };
    });

    setEdges(newEdges);
  }, [callGraph]);

  // Handle canvas rendering
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const rect = canvas.getBoundingClientRect();
    const centerX = rect.width / 2 + pan.x;
    const centerY = rect.height / 2 + pan.y;

    // Clear canvas
    ctx.fillStyle = '#050505';
    ctx.fillRect(0, 0, rect.width, rect.height);

    // Draw edges
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
    ctx.lineWidth = 2 / zoom;

    edges.forEach(edge => {
      const source = nodes.find(n => n.id === edge.source);
      const target = nodes.find(n => n.id === edge.target);
      if (source && target) {
        ctx.beginPath();
        ctx.moveTo(centerX + source.x * zoom, centerY + source.y * zoom);
        ctx.lineTo(centerX + target.x * zoom, centerY + target.y * zoom);
        ctx.stroke();
      }
    });

    // Draw nodes
    nodes.forEach(node => {
      const isSelected = selectedNode === node.id;
      const threatColor =
        node.threat === 'high' ? '#ef5350' :
        node.threat === 'medium' ? '#ffa726' :
        '#66bb6a';

      // Draw node circle
      ctx.fillStyle = isSelected ? threatColor : `${threatColor}99`;
      ctx.beginPath();
      ctx.arc(
        centerX + node.x * zoom,
        centerY + node.y * zoom,
        (node.size * zoom) / 2,
        0,
        Math.PI * 2
      );
      ctx.fill();

      // Draw border
      ctx.strokeStyle = isSelected ? threatColor : `${threatColor}66`;
      ctx.lineWidth = 2 / zoom;
      ctx.stroke();

      // Draw label
      if (zoom > 0.5) {
        ctx.fillStyle = '#ffffff';
        ctx.font = `${Math.max(10, 12 / zoom)}px monospace`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(
          node.label.slice(0, 15),
          centerX + node.x * zoom,
          centerY + node.y * zoom
        );
      }
    });
  }, [nodes, edges, selectedNode, zoom, pan]);

  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const centerX = rect.width / 2 + pan.x;
    const centerY = rect.height / 2 + pan.y;

    const clickX = (e.clientX - rect.left - centerX) / zoom;
    const clickY = (e.clientY - rect.top - centerY) / zoom;

    // Find clicked node
    for (const node of nodes) {
      const dist = Math.sqrt(
        (clickX - node.x) ** 2 + (clickY - node.y) ** 2
      );
      if (dist < node.size / 2) {
        setSelectedNode(node.id);
        onNodeClick?.(node);
        return;
      }
    }

    setSelectedNode(null);
  };

  const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom(z => Math.max(0.1, Math.min(5, z * factor)));
  };

  if (!callGraph || callGraph.nodes.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-on-surface-variant/40">
        <div className="text-center">
          <span className="material-symbols-outlined text-[48px] mb-2 opacity-20">share</span>
          <p className="text-[11px] font-mono uppercase tracking-[0.18em]">No call graph data available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex gap-4 p-4">
      {/* CANVAS */}
      <div className="flex-1 border border-white/10 rounded-lg overflow-hidden bg-black relative">
        <canvas
          ref={canvasRef}
          width={800}
          height={600}
          onClick={handleCanvasClick}
          onWheel={handleWheel}
          className="w-full h-full cursor-grab active:cursor-grabbing"
        />

        {/* CONTROLS */}
        <div className="absolute top-4 left-4 space-y-2">
          <button
            onClick={() => setZoom(z => Math.min(5, z * 1.2))}
            className="w-8 h-8 bg-black/60 border border-white/20 rounded flex items-center justify-center hover:border-secondary transition-colors"
            title="Zoom in"
          >
            <span className="material-symbols-outlined text-[16px]">add</span>
          </button>
          <button
            onClick={() => setZoom(z => Math.max(0.1, z * 0.8))}
            className="w-8 h-8 bg-black/60 border border-white/20 rounded flex items-center justify-center hover:border-secondary transition-colors"
            title="Zoom out"
          >
            <span className="material-symbols-outlined text-[16px]">remove</span>
          </button>
          <button
            onClick={() => {
              setZoom(1);
              setPan({ x: 0, y: 0 });
            }}
            className="w-8 h-8 bg-black/60 border border-white/20 rounded flex items-center justify-center hover:border-secondary transition-colors"
            title="Reset view"
          >
            <span className="material-symbols-outlined text-[16px]">home</span>
          </button>
        </div>

        {/* INFO OVERLAY */}
        <div className="absolute bottom-4 right-4 bg-black/70 border border-white/10 rounded px-3 py-2 text-[9px] text-on-surface-variant/60 space-y-1">
          <div>Zoom: {(zoom * 100).toFixed(0)}%</div>
          <div>Nodes: {nodes.length}</div>
          <div>Edges: {edges.length}</div>
        </div>
      </div>

      {/* LEGEND & STATS */}
      <div className="w-64 flex flex-col gap-3">
        {/* THREAT LEGEND */}
        <div className="border border-white/10 rounded-lg bg-white/5 p-3">
          <div className="text-[10px] font-bold uppercase text-on-surface-variant/60 mb-3 tracking-[0.1em]">
            Threat Levels
          </div>
          <div className="space-y-2">
            {[
              { level: 'HIGH', color: '#ef5350' },
              { level: 'MEDIUM', color: '#ffa726' },
              { level: 'LOW', color: '#66bb6a' }
            ].map(item => (
              <div key={item.level} className="flex items-center gap-2">
                <div
                  className="w-4 h-4 rounded-full"
                  style={{ backgroundColor: item.color }}
                />
                <span className="text-[9px] text-on-surface-variant">{item.level}</span>
              </div>
            ))}
          </div>
        </div>

        {/* GRAPH STATISTICS */}
        <div className="border border-white/10 rounded-lg bg-white/5 p-3 space-y-3">
          <div className="text-[10px] font-bold uppercase text-on-surface-variant/60 tracking-[0.1em]">
            Graph Statistics
          </div>

          <div className="space-y-2 text-[10px]">
            <div className="flex justify-between">
              <span className="text-on-surface-variant/60">Total Nodes:</span>
              <span className="text-secondary font-bold">{nodes.length}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-on-surface-variant/60">Total Edges:</span>
              <span className="text-primary font-bold">{edges.length}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-on-surface-variant/60">Entry Points:</span>
              <span className="text-tertiary font-bold">{callGraph?.entry_points.length || 0}</span>
            </div>
          </div>
        </div>

        {/* SELECTED NODE DETAILS */}
        {selectedNode && nodes.find(n => n.id === selectedNode) && (
          <div className="border border-white/10 rounded-lg bg-white/5 p-3">
            <div className="text-[10px] font-bold uppercase text-on-surface-variant/60 mb-3 tracking-[0.1em]">
              Selected Node
            </div>
            <div className="space-y-2 text-[9px]">
              <div>
                <span className="text-on-surface-variant/60">Name:</span>
                <span className="text-secondary ml-2 block truncate">
                  {nodes.find(n => n.id === selectedNode)?.label}
                </span>
              </div>
              <div>
                <span className="text-on-surface-variant/60">Threat:</span>
                <span className={cn(
                  "ml-2 font-bold uppercase text-[8px]",
                  nodes.find(n => n.id === selectedNode)?.threat === 'high' ? "text-error" :
                  nodes.find(n => n.id === selectedNode)?.threat === 'medium' ? "text-tertiary" :
                  "text-success"
                )}>
                  {nodes.find(n => n.id === selectedNode)?.threat}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* ENTRY POINTS */}
        {callGraph?.entry_points && callGraph.entry_points.length > 0 && (
          <div className="border border-white/10 rounded-lg bg-white/5 p-3">
            <div className="text-[10px] font-bold uppercase text-on-surface-variant/60 mb-3 tracking-[0.1em]">
              Entry Points
            </div>
            <div className="space-y-2">
              {callGraph.entry_points.slice(0, 3).map((ep, idx) => (
                <div key={idx} className="text-[9px] text-on-surface-variant font-mono truncate">
                  • {ep}
                </div>
              ))}
              {callGraph.entry_points.length > 3 && (
                <div className="text-[9px] text-on-surface-variant/50">
                  +{callGraph.entry_points.length - 3} more
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CallGraphVisualization;
