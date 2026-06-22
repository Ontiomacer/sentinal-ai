import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Bot,
  Boxes,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Clock3,
  Crosshair,
  Filter,
  Focus,
  GitBranch,
  Layers3,
  ListFilter,
  Maximize2,
  MoreHorizontal,
  Network,
  PanelRightOpen,
  RotateCcw,
  Search,
  ShieldCheck,
  X,
  ZoomIn,
  ZoomOut
} from 'lucide-react'
import { select, zoom, zoomIdentity, ZoomBehavior } from 'd3'
import { Evidence } from '../../services/caseApi'
import {
  buildInvestigationGraph,
  buildWorkflowStages,
  extractThreatNarrative,
  InvestigationEdge,
  InvestigationGraphModel,
  InvestigationNode,
  InvestigationNodeKind,
  RelationshipKind,
  Severity,
  ThreatNarrative,
  WorkflowStage,
  WorkflowStatus
} from './investigationModel'

interface ThreatInvestigationWorkspaceProps {
  evidence: Evidence | null
  analysisResult: unknown
}

interface ContextMenuState {
  x: number
  y: number
  nodeId: string
}

type InspectorTab = 'evidence' | 'narrative'

const PAGE_SIZE = 18

const kindStyles: Record<InvestigationNodeKind, { accent: string; fill: string; code: string }> = {
  apk: { accent: '#22d3ee', fill: '#06252b', code: 'APK' },
  group: { accent: '#a3a3a3', fill: '#171717', code: 'SET' },
  manifest: { accent: '#c084fc', fill: '#21142d', code: 'MF' },
  permission: { accent: '#34d399', fill: '#0b251d', code: 'PM' },
  activity: { accent: '#60a5fa', fill: '#0d1e35', code: 'AC' },
  service: { accent: '#38bdf8', fill: '#0b2230', code: 'SV' },
  receiver: { accent: '#818cf8', fill: '#171a36', code: 'RC' },
  provider: { accent: '#a78bfa', fill: '#1d1734', code: 'PV' },
  string: { accent: '#d4d4d8', fill: '#1c1c1f', code: 'ST' },
  certificate: { accent: '#facc15', fill: '#2b2508', code: 'CRT' },
  domain: { accent: '#fbbf24', fill: '#2a1d07', code: 'DM' },
  url: { accent: '#fb923c', fill: '#2b1508', code: 'URL' },
  ip: { accent: '#f97316', fill: '#2a1208', code: 'IP' },
  finding: { accent: '#fb7185', fill: '#301018', code: 'FD' },
  ioc: { accent: '#f59e0b', fill: '#291a05', code: 'IOC' },
  risk: { accent: '#f43f5e', fill: '#310c15', code: 'RSK' },
  recommendation: { accent: '#a3e635', fill: '#172407', code: 'ACT' },
  function: { accent: '#2dd4bf', fill: '#072823', code: 'FN' },
  library: { accent: '#94a3b8', fill: '#17202a', code: 'LIB' }
}

const relationshipColors: Record<RelationshipKind, string> = {
  evidence: '#64748b',
  analysis: '#22d3ee',
  correlation: '#f59e0b',
  assessment: '#fb7185'
}

const statusStyles: Record<WorkflowStatus, { label: string; color: string; background: string }> = {
  completed: { label: 'Completed', color: '#4ade80', background: '#102619' },
  running: { label: 'Running', color: '#22d3ee', background: '#08262d' },
  failed: { label: 'Failed', color: '#fb7185', background: '#301018' },
  pending: { label: 'Pending', color: '#737373', background: '#171717' }
}

const severityClasses: Record<Severity, string> = {
  critical: 'border-rose-400/50 bg-rose-400/10 text-rose-300',
  high: 'border-orange-400/50 bg-orange-400/10 text-orange-300',
  medium: 'border-amber-300/50 bg-amber-300/10 text-amber-200',
  low: 'border-emerald-400/50 bg-emerald-400/10 text-emerald-300',
  info: 'border-zinc-500/50 bg-zinc-500/10 text-zinc-300'
}

const clampConfidence = (value: number): number => Math.max(0, Math.min(100, value <= 1 ? value * 100 : value))

const edgePath = (source: InvestigationNode, target: InvestigationNode): string => {
  const sourceX = source.x + source.width / 2
  const targetX = target.x - target.width / 2
  const controlOffset = Math.max(70, (targetX - sourceX) * 0.45)
  return `M ${sourceX} ${source.y} C ${sourceX + controlOffset} ${source.y}, ${targetX - controlOffset} ${target.y}, ${targetX} ${target.y}`
}

const shortText = (value: string, maxLength: number): string =>
  value.length > maxLength ? `${value.slice(0, maxLength - 3)}...` : value

const NodeGlyph = ({ node }: { node: InvestigationNode }) => {
  const style = kindStyles[node.kind]
  return (
    <text
      x={-node.width / 2 + 31}
      y={node.kind === 'apk' ? 2 : 1}
      fill={style.accent}
      fontSize={style.code.length > 2 ? 8 : 9}
      fontWeight="700"
      textAnchor="middle"
      dominantBaseline="middle"
      className="pointer-events-none font-mono"
    >
      {style.code}
    </text>
  )
}

const WorkflowNode = ({ stage, selected, onSelect }: { stage: WorkflowStage; selected: boolean; onSelect: () => void }) => {
  const status = statusStyles[stage.status]
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`relative h-[86px] w-[206px] shrink-0 border text-left transition-colors ${
        selected ? 'border-cyan-300/70 bg-cyan-300/[0.07]' : 'border-white/10 bg-[#0c0c0e] hover:border-white/25'
      }`}
    >
      <span className="absolute left-0 top-0 h-full w-1" style={{ background: status.color }} />
      <span className="flex h-full flex-col justify-between px-3 py-2 pl-4">
        <span className="flex items-start justify-between gap-2">
          <span className="min-w-0">
            <span className="block truncate font-mono text-[10px] text-zinc-500">{stage.agent}</span>
            <span className="mt-0.5 block truncate text-xs font-semibold text-zinc-100">{stage.label}</span>
          </span>
          <span
            className={`mt-0.5 h-2.5 w-2.5 shrink-0 rounded-full ${stage.status === 'running' ? 'animate-pulse' : ''}`}
            style={{ background: status.color, boxShadow: stage.status === 'running' ? `0 0 10px ${status.color}` : 'none' }}
          />
        </span>
        <span className="flex items-center justify-between gap-2 font-mono text-[9px]">
          <span className="truncate text-zinc-600">OUT: {stage.output}</span>
          <span className="shrink-0" style={{ color: status.color }}>{status.label}</span>
        </span>
      </span>
    </button>
  )
}

const SectionTitle = ({ children }: { children: string }) => (
  <div className="mb-2 flex items-center gap-2 font-mono text-[10px] uppercase text-zinc-500">
    <span className="h-px w-4 bg-zinc-700" />
    {children}
  </div>
)

const EmptyValue = ({ children }: { children: string }) => (
  <p className="font-mono text-[11px] leading-5 text-zinc-600">{children}</p>
)

const NarrativePanel = ({ narrative }: { narrative: ThreatNarrative }) => (
  <div className="divide-y divide-white/[0.07]">
    <section className="px-4 py-4">
      <SectionTitle>Executive Summary</SectionTitle>
      {narrative.executiveSummary
        ? <p className="text-xs leading-5 text-zinc-300">{narrative.executiveSummary}</p>
        : <EmptyValue>No executive summary was returned by this analysis.</EmptyValue>}
    </section>

    {(narrative.riskScore !== undefined || narrative.severity || narrative.confidence !== undefined) && (
      <section className="grid grid-cols-3 divide-x divide-white/[0.07] px-4 py-3 text-center">
        <div>
          <div className="font-mono text-[9px] uppercase text-zinc-600">Risk</div>
          <div className="mt-1 text-lg font-semibold text-rose-300">{narrative.riskScore ?? '--'}</div>
        </div>
        <div>
          <div className="font-mono text-[9px] uppercase text-zinc-600">Severity</div>
          <div className="mt-2 font-mono text-[10px] uppercase text-zinc-300">{narrative.severity || '--'}</div>
        </div>
        <div>
          <div className="font-mono text-[9px] uppercase text-zinc-600">Confidence</div>
          <div className="mt-1 text-lg font-semibold text-cyan-300">{narrative.confidence ?? '--'}</div>
        </div>
      </section>
    )}

    <section className="px-4 py-4">
      <SectionTitle>Key Findings</SectionTitle>
      {narrative.keyFindings.length ? (
        <ul className="space-y-2">
          {narrative.keyFindings.map((finding, index) => (
            <li key={`${finding}-${index}`} className="flex gap-2 text-xs leading-5 text-zinc-300">
              <CircleDot className="mt-1 h-3 w-3 shrink-0 text-rose-300" />
              <span>{finding}</span>
            </li>
          ))}
        </ul>
      ) : <EmptyValue>No key findings were returned by this analysis.</EmptyValue>}
    </section>

    <section className="px-4 py-4">
      <SectionTitle>Threat Assessment</SectionTitle>
      {narrative.threatAssessment
        ? <p className="text-xs leading-5 text-zinc-300">{narrative.threatAssessment}</p>
        : <EmptyValue>No threat assessment narrative was returned.</EmptyValue>}
    </section>

    <section className="px-4 py-4">
      <SectionTitle>Potential Abuse Scenarios</SectionTitle>
      {narrative.abuseScenarios.length ? (
        <ul className="space-y-2 text-xs leading-5 text-zinc-300">
          {narrative.abuseScenarios.map((scenario, index) => <li key={`${scenario}-${index}`}>{index + 1}. {scenario}</li>)}
        </ul>
      ) : <EmptyValue>No abuse scenarios were returned by this analysis.</EmptyValue>}
    </section>

    <section className="px-4 py-4">
      <SectionTitle>Risk Score Explanation</SectionTitle>
      {narrative.riskExplanation
        ? <p className="text-xs leading-5 text-zinc-300">{narrative.riskExplanation}</p>
        : <EmptyValue>No score explanation was returned by this analysis.</EmptyValue>}
    </section>

    <section className="px-4 py-4">
      <SectionTitle>Recommended Actions</SectionTitle>
      {narrative.recommendedActions.length ? (
        <ul className="space-y-2">
          {narrative.recommendedActions.map((action, index) => (
            <li key={`${action}-${index}`} className="flex gap-2 text-xs leading-5 text-zinc-300">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-lime-300" />
              <span>{action}</span>
            </li>
          ))}
        </ul>
      ) : <EmptyValue>No recommended actions were returned by this analysis.</EmptyValue>}
    </section>
  </div>
)

interface InspectorProps {
  tab: InspectorTab
  onTabChange: (tab: InspectorTab) => void
  node: InvestigationNode | null
  stage: WorkflowStage | null
  relationships: Array<{ edge: InvestigationEdge; node: InvestigationNode }>
  narrative: ThreatNarrative
  onClose?: () => void
}

const Inspector = ({ tab, onTabChange, node, stage, relationships, narrative, onClose }: InspectorProps) => (
  <aside className="flex h-full min-h-0 flex-col border-l border-white/10 bg-[#09090b]">
    <div className="flex h-11 shrink-0 items-center justify-between border-b border-white/10 px-3">
      <div className="flex h-8 items-center border border-white/10 bg-black/40 p-0.5">
        <button
          type="button"
          onClick={() => onTabChange('evidence')}
          className={`h-7 px-3 font-mono text-[10px] uppercase ${tab === 'evidence' ? 'bg-zinc-200 text-black' : 'text-zinc-500 hover:text-zinc-200'}`}
        >
          Evidence
        </button>
        <button
          type="button"
          onClick={() => onTabChange('narrative')}
          className={`h-7 px-3 font-mono text-[10px] uppercase ${tab === 'narrative' ? 'bg-zinc-200 text-black' : 'text-zinc-500 hover:text-zinc-200'}`}
        >
          Narrative
        </button>
      </div>
      {onClose && (
        <button type="button" onClick={onClose} title="Close inspector" className="grid h-8 w-8 place-items-center text-zinc-500 hover:text-white">
          <X className="h-4 w-4" />
        </button>
      )}
    </div>

    <div className="min-h-0 flex-1 overflow-y-auto custom-scrollbar">
      {tab === 'narrative' ? <NarrativePanel narrative={narrative} /> : stage ? (
        <div className="divide-y divide-white/[0.07]">
          <section className="px-4 py-4">
            <div className="mb-2 flex items-center justify-between gap-3">
              <span className="font-mono text-[10px] uppercase text-cyan-300">{stage.agent}</span>
              <span className="border px-2 py-0.5 font-mono text-[9px] uppercase" style={{ borderColor: statusStyles[stage.status].color, color: statusStyles[stage.status].color }}>
                {statusStyles[stage.status].label}
              </span>
            </div>
            <h2 className="text-base font-semibold text-white">{stage.label}</h2>
          </section>
          <section className="px-4 py-4">
            <SectionTitle>Purpose</SectionTitle>
            <p className="text-xs leading-5 text-zinc-300">{stage.purpose}</p>
          </section>
          <section className="grid grid-cols-2 divide-x divide-white/[0.07] px-4 py-4">
            <div className="pr-3">
              <SectionTitle>Input</SectionTitle>
              <p className="font-mono text-[11px] text-zinc-300">{stage.input}</p>
            </div>
            <div className="pl-3">
              <SectionTitle>Output</SectionTitle>
              <p className="font-mono text-[11px] text-zinc-300">{stage.output}</p>
            </div>
          </section>
        </div>
      ) : node ? (
        <div className="divide-y divide-white/[0.07]">
          <section className="px-4 py-4">
            <div className="mb-2 flex items-center gap-2">
              <span className="font-mono text-[10px] uppercase" style={{ color: kindStyles[node.kind].accent }}>{node.kind}</span>
              {node.severity && <span className={`border px-1.5 py-0.5 font-mono text-[9px] uppercase ${severityClasses[node.severity]}`}>{node.severity}</span>}
            </div>
            <h2 className="break-words text-base font-semibold leading-6 text-white">{node.label}</h2>
            {node.subtitle && <p className="mt-1 break-words font-mono text-[10px] text-zinc-500">{node.subtitle}</p>}
          </section>

          <section className="px-4 py-4">
            <SectionTitle>Purpose</SectionTitle>
            <p className="text-xs leading-5 text-zinc-300">{node.purpose}</p>
          </section>

          <section className="px-4 py-4">
            <SectionTitle>Evidence</SectionTitle>
            {node.evidence.length ? (
              <ul className="space-y-2 font-mono text-[11px] leading-5 text-zinc-300">
                {node.evidence.map((item, index) => <li key={`${item}-${index}`} className="break-words border-l border-cyan-400/40 pl-2">{item}</li>)}
              </ul>
            ) : <EmptyValue>No additional evidence was attached to this artifact.</EmptyValue>}
          </section>

          <section className="px-4 py-4">
            <SectionTitle>Relationships</SectionTitle>
            {relationships.length ? (
              <ul className="space-y-2">
                {relationships.map(({ edge, node: relatedNode }) => (
                  <li key={edge.id} className="flex items-start justify-between gap-3 text-[11px]">
                    <span className="min-w-0 break-words text-zinc-300">{relatedNode.label}</span>
                    <span className="shrink-0 font-mono text-[9px] text-zinc-600">{edge.label}</span>
                  </li>
                ))}
              </ul>
            ) : <EmptyValue>No visible relationships for this artifact.</EmptyValue>}
          </section>

          <section className="px-4 py-4">
            <SectionTitle>Reasoning</SectionTitle>
            {node.reasoning
              ? <p className="text-xs leading-5 text-zinc-300">{node.reasoning}</p>
              : <EmptyValue>No reasoning text was returned for this artifact.</EmptyValue>}
          </section>

          {(node.riskScore !== undefined || node.confidence !== undefined || node.riskImpact) && (
            <section className="px-4 py-4">
              <SectionTitle>Risk Impact & Confidence</SectionTitle>
              {node.riskImpact && <p className="mb-3 text-xs leading-5 text-zinc-300">{node.riskImpact}</p>}
              <div className="space-y-3">
                {node.riskScore !== undefined && (
                  <div>
                    <div className="mb-1 flex justify-between font-mono text-[9px] uppercase text-zinc-500"><span>Risk score</span><span>{node.riskScore}/100</span></div>
                    <div className="h-1.5 bg-zinc-900"><div className="h-full bg-rose-400" style={{ width: `${Math.max(0, Math.min(100, node.riskScore))}%` }} /></div>
                  </div>
                )}
                {node.confidence !== undefined && (
                  <div>
                    <div className="mb-1 flex justify-between font-mono text-[9px] uppercase text-zinc-500"><span>Confidence</span><span>{Math.round(clampConfidence(node.confidence))}%</span></div>
                    <div className="h-1.5 bg-zinc-900"><div className="h-full bg-cyan-400" style={{ width: `${clampConfidence(node.confidence)}%` }} /></div>
                  </div>
                )}
              </div>
            </section>
          )}

          <section className="px-4 py-4">
            <SectionTitle>Investigation Recommendations</SectionTitle>
            {node.recommendations.length ? (
              <ul className="space-y-2 text-xs leading-5 text-zinc-300">
                {node.recommendations.map((item, index) => <li key={`${item}-${index}`}>{index + 1}. {item}</li>)}
              </ul>
            ) : <EmptyValue>No node-specific recommendation was returned.</EmptyValue>}
          </section>

          <section className="px-4 py-4">
            <SectionTitle>Supporting Artifacts</SectionTitle>
            {node.artifacts.length ? (
              <dl className="divide-y divide-white/[0.05]">
                {node.artifacts.map(item => (
                  <div key={`${item.label}-${item.value}`} className="grid grid-cols-[92px_minmax(0,1fr)] gap-3 py-2 font-mono text-[10px]">
                    <dt className="text-zinc-600">{item.label}</dt>
                    <dd className="break-words text-zinc-300">{item.value}</dd>
                  </div>
                ))}
              </dl>
            ) : <EmptyValue>No additional artifact fields were returned.</EmptyValue>}
          </section>
        </div>
      ) : (
        <div className="grid h-full place-items-center px-8 text-center">
          <div>
            <Crosshair className="mx-auto mb-3 h-7 w-7 text-zinc-700" />
            <p className="text-xs text-zinc-400">Select an entity or workflow node to inspect its evidence and reasoning.</p>
          </div>
        </div>
      )}
    </div>
  </aside>
)

const Timeline = ({ evidence, stages, onStageSelect }: { evidence: Evidence | null; stages: WorkflowStage[]; onStageSelect: (stage: WorkflowStage) => void }) => {
  const events = evidence
    ? [{ id: 'imported', label: 'APK Imported', status: 'completed' as WorkflowStatus, timestamp: evidence.created_at }, ...stages.map(stage => ({ id: stage.id, label: stage.label.replace(' Analysis', ' Analyzed'), status: stage.status, timestamp: stage.id === 'narrative' ? evidence.analyzed_at : undefined }))]
    : stages.map(stage => ({ id: stage.id, label: stage.label, status: 'pending' as WorkflowStatus, timestamp: undefined }))

  return (
    <div className="h-[104px] shrink-0 border-t border-white/10 bg-[#08080a]">
      <div className="flex h-8 items-center gap-2 border-b border-white/[0.07] px-3 font-mono text-[10px] uppercase text-zinc-500">
        <Clock3 className="h-3.5 w-3.5" />
        Investigation Timeline
        <span className="ml-auto text-[9px] text-zinc-700">Synchronized with execution state</span>
      </div>
      <div className="flex h-[72px] items-center overflow-x-auto px-4 hide-scrollbar">
        {events.map((event, index) => (
          <div key={event.id} className="flex shrink-0 items-center">
            <button type="button" onClick={() => stages.find(stage => stage.id === event.id) && onStageSelect(stages.find(stage => stage.id === event.id) as WorkflowStage)} className="group w-[142px] text-left">
              <span className="flex items-center gap-2">
                <span className={`h-2.5 w-2.5 rounded-full ${event.status === 'running' ? 'animate-pulse' : ''}`} style={{ background: statusStyles[event.status].color }} />
                <span className="truncate font-mono text-[9px] uppercase text-zinc-400 group-hover:text-white">{event.label}</span>
              </span>
              <span className="mt-1 block truncate pl-[18px] font-mono text-[8px] text-zinc-700">
                {event.timestamp ? new Date(event.timestamp).toLocaleString() : statusStyles[event.status].label}
              </span>
            </button>
            {index < events.length - 1 && <span className="mx-2 h-px w-7 bg-zinc-800" />}
          </div>
        ))}
      </div>
    </div>
  )
}

const ThreatInvestigationWorkspace = ({ evidence, analysisResult }: ThreatInvestigationWorkspaceProps) => {
  const svgRef = useRef<SVGSVGElement>(null)
  const viewportRef = useRef<SVGGElement>(null)
  const canvasRef = useRef<HTMLDivElement>(null)
  const zoomBehaviorRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null)
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [groupLimits, setGroupLimits] = useState<Record<string, number>>({})
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [selectedStageId, setSelectedStageId] = useState<string | null>(null)
  const [hiddenNodeIds, setHiddenNodeIds] = useState<Set<string>>(new Set())
  const [focusNodeId, setFocusNodeId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all')
  const [relationshipFilter, setRelationshipFilter] = useState<'all' | RelationshipKind>('all')
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null)
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>('narrative')
  const [mobileInspectorOpen, setMobileInspectorOpen] = useState(false)

  const stages = useMemo(() => buildWorkflowStages(evidence, analysisResult), [evidence, analysisResult])
  const narrative = useMemo(() => extractThreatNarrative(analysisResult), [analysisResult])
  const model = useMemo<InvestigationGraphModel | null>(() => {
    if (!evidence) return null
    return buildInvestigationGraph(evidence, analysisResult, expandedGroups, groupLimits)
  }, [evidence, analysisResult, expandedGroups, groupLimits])

  useEffect(() => {
    setExpandedGroups(new Set(['group:manifest', 'group:findings', 'group:risk']))
    setGroupLimits({})
    setSelectedNodeId(null)
    setSelectedStageId(null)
    setHiddenNodeIds(new Set())
    setFocusNodeId(null)
    setInspectorTab('narrative')
  }, [evidence?.id])

  const fitGraph = useCallback((graphModel = model) => {
    const svg = svgRef.current
    const behavior = zoomBehaviorRef.current
    if (!svg || !behavior || !graphModel) return
    const width = svg.clientWidth
    const height = svg.clientHeight
    if (!width || !height) return
    const boundsWidth = graphModel.bounds.maxX - graphModel.bounds.minX
    const boundsHeight = graphModel.bounds.maxY - graphModel.bounds.minY
    const scale = Math.max(0.28, Math.min(1.1, (width - 120) / boundsWidth, (height - 100) / boundsHeight))
    const translateX = (width - boundsWidth * scale) / 2 - graphModel.bounds.minX * scale
    const translateY = (height - boundsHeight * scale) / 2 - graphModel.bounds.minY * scale
    select(svg).transition().duration(280).call(behavior.transform, zoomIdentity.translate(translateX, translateY).scale(scale))
  }, [model])

  useEffect(() => {
    const svg = svgRef.current
    const viewport = viewportRef.current
    if (!svg || !viewport) return
    const behavior = zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 2.6])
      .filter(event => !event.ctrlKey || event.type === 'wheel')
      .on('zoom', event => select(viewport).attr('transform', event.transform.toString()))
    zoomBehaviorRef.current = behavior
    select(svg).call(behavior)
    return () => {
      select(svg).on('.zoom', null)
      zoomBehaviorRef.current = null
    }
  }, [])

  useEffect(() => {
    if (!model) return
    const frame = window.requestAnimationFrame(() => fitGraph(model))
    return () => window.cancelAnimationFrame(frame)
  }, [evidence?.id, fitGraph, model])

  const visibleNodes = useMemo(() => {
    if (!model) return []
    return model.nodes.filter(node => {
      if (hiddenNodeIds.has(node.id)) return false
      if (severityFilter !== 'all' && node.kind !== 'apk' && node.kind !== 'group' && node.severity !== severityFilter) return false
      return true
    })
  }, [model, hiddenNodeIds, severityFilter])

  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map(node => node.id)), [visibleNodes])
  const visibleEdges = useMemo(() => {
    if (!model) return []
    return model.edges.filter(edge =>
      visibleNodeIds.has(edge.source)
      && visibleNodeIds.has(edge.target)
      && (relationshipFilter === 'all' || edge.kind === relationshipFilter)
    )
  }, [model, relationshipFilter, visibleNodeIds])

  const focusedNodeIds = useMemo(() => {
    if (!model || !focusNodeId) return null
    const ids = new Set([focusNodeId])
    model.edges.forEach(edge => {
      if (edge.source === focusNodeId) ids.add(edge.target)
      if (edge.target === focusNodeId) ids.add(edge.source)
    })
    return ids
  }, [model, focusNodeId])

  const selectedNode = model?.nodes.find(node => node.id === selectedNodeId) || null
  const selectedStage = stages.find(stage => stage.id === selectedStageId) || null
  const relationships = useMemo(() => {
    if (!model || !selectedNode) return []
    return model.edges.flatMap(edge => {
      if (edge.source === selectedNode.id) {
        const node = model.nodes.find(candidate => candidate.id === edge.target)
        return node ? [{ edge, node }] : []
      }
      if (edge.target === selectedNode.id) {
        const node = model.nodes.find(candidate => candidate.id === edge.source)
        return node ? [{ edge, node }] : []
      }
      return []
    })
  }, [model, selectedNode])

  const toggleGroup = (groupId: string) => {
    setExpandedGroups(current => {
      const next = new Set(current)
      if (next.has(groupId)) next.delete(groupId)
      else next.add(groupId)
      return next
    })
  }

  const loadMore = (groupId: string) => {
    setGroupLimits(current => ({ ...current, [groupId]: (current[groupId] || PAGE_SIZE) + PAGE_SIZE }))
  }

  const selectNode = (node: InvestigationNode) => {
    setSelectedNodeId(node.id)
    setSelectedStageId(null)
    setInspectorTab('evidence')
    setMobileInspectorOpen(true)
  }

  const selectStage = (stage: WorkflowStage) => {
    setSelectedStageId(stage.id)
    setSelectedNodeId(null)
    setInspectorTab('evidence')
    setMobileInspectorOpen(true)
  }

  const focusNode = (node: InvestigationNode) => {
    const svg = svgRef.current
    const behavior = zoomBehaviorRef.current
    if (!svg || !behavior) return
    const scale = 1.25
    const x = svg.clientWidth / 2 - node.x * scale
    const y = svg.clientHeight / 2 - node.y * scale
    select(svg).transition().duration(240).call(behavior.transform, zoomIdentity.translate(x, y).scale(scale))
    setFocusNodeId(node.id)
  }

  const zoomBy = (factor: number) => {
    if (svgRef.current && zoomBehaviorRef.current) {
      select(svgRef.current).transition().duration(160).call(zoomBehaviorRef.current.scaleBy, factor)
    }
  }

  const resetView = () => {
    setHiddenNodeIds(new Set())
    setFocusNodeId(null)
    setSearch('')
    setSeverityFilter('all')
    setRelationshipFilter('all')
    fitGraph()
  }

  const contextNode = contextMenu && model ? model.nodes.find(node => node.id === contextMenu.nodeId) || null : null
  const searchValue = search.trim().toLowerCase()

  return (
    <div className="flex h-full min-h-0 flex-col bg-[#060607] text-zinc-200" onClick={() => setContextMenu(null)}>
      <section className="h-[122px] shrink-0 border-b border-white/10 bg-[#08080a]">
        <div className="flex h-8 items-center justify-between border-b border-white/[0.07] px-3">
          <div className="flex items-center gap-2 font-mono text-[10px] uppercase text-zinc-500">
            <Bot className="h-3.5 w-3.5 text-cyan-300" />
            Agentic Execution Graph
          </div>
          <div className="flex items-center gap-3 font-mono text-[9px] uppercase text-zinc-600">
            <span>{stages.filter(stage => stage.status === 'completed').length}/{stages.length} stages complete</span>
            <span className="hidden md:inline">Inputs and outputs remain analysis-backed</span>
          </div>
        </div>
        <div className="flex h-[94px] items-center overflow-x-auto px-3 hide-scrollbar">
          {stages.map((stage, index) => (
            <div key={stage.id} className="flex shrink-0 items-center">
              <WorkflowNode stage={stage} selected={selectedStageId === stage.id} onSelect={() => selectStage(stage)} />
              {index < stages.length - 1 && (
                <div className="relative mx-1.5 w-8 shrink-0">
                  <div className="h-px bg-zinc-700" />
                  <ChevronRight className="absolute -right-1 -top-1.5 h-3 w-3 text-zinc-600" />
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      <div className="relative grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[minmax(0,1fr)_340px] xl:grid-cols-[minmax(0,1fr)_380px]">
        <main ref={canvasRef} className="relative min-h-0 overflow-hidden bg-[#070709]">
          <div className="absolute inset-x-0 top-0 z-20 flex h-11 items-center gap-2 border-b border-white/10 bg-[#09090b]/95 px-2 backdrop-blur">
            <div className="relative min-w-0 flex-1 sm:max-w-[270px]">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-zinc-600" />
              <input
                value={search}
                onChange={event => setSearch(event.target.value)}
                placeholder="Search graph entities"
                aria-label="Search graph entities"
                disabled={!model}
                className="h-8 w-full border border-white/10 bg-black/50 pl-8 pr-3 font-mono text-[10px] text-zinc-200 outline-none placeholder:text-zinc-700 focus:border-cyan-400/50 disabled:opacity-40"
              />
            </div>

            <div className="relative hidden sm:block">
              <Filter className="pointer-events-none absolute left-2 top-2.5 h-3 w-3 text-zinc-600" />
              <select
                value={severityFilter}
                onChange={event => setSeverityFilter(event.target.value as 'all' | Severity)}
                aria-label="Filter by severity"
                className="h-8 appearance-none border border-white/10 bg-black/50 pl-7 pr-7 font-mono text-[9px] uppercase text-zinc-400 outline-none"
              >
                <option value="all">All severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
              <ChevronDown className="pointer-events-none absolute right-2 top-2.5 h-3 w-3 text-zinc-600" />
            </div>

            <div className="relative hidden md:block">
              <GitBranch className="pointer-events-none absolute left-2 top-2.5 h-3 w-3 text-zinc-600" />
              <select
                value={relationshipFilter}
                onChange={event => setRelationshipFilter(event.target.value as 'all' | RelationshipKind)}
                aria-label="Filter relationships"
                className="h-8 appearance-none border border-white/10 bg-black/50 pl-7 pr-7 font-mono text-[9px] uppercase text-zinc-400 outline-none"
              >
                <option value="all">All relations</option>
                <option value="evidence">Evidence</option>
                <option value="analysis">Analysis</option>
                <option value="correlation">Correlation</option>
                <option value="assessment">Assessment</option>
              </select>
              <ChevronDown className="pointer-events-none absolute right-2 top-2.5 h-3 w-3 text-zinc-600" />
            </div>

            <div className="ml-auto flex shrink-0 items-center border border-white/10 bg-black/40">
              <button type="button" onClick={() => zoomBy(1.25)} title="Zoom in" className="grid h-8 w-8 place-items-center text-zinc-500 hover:bg-white/5 hover:text-white"><ZoomIn className="h-3.5 w-3.5" /></button>
              <button type="button" onClick={() => zoomBy(0.8)} title="Zoom out" className="grid h-8 w-8 place-items-center border-l border-white/10 text-zinc-500 hover:bg-white/5 hover:text-white"><ZoomOut className="h-3.5 w-3.5" /></button>
              <button type="button" onClick={() => fitGraph()} title="Fit graph" className="grid h-8 w-8 place-items-center border-l border-white/10 text-zinc-500 hover:bg-white/5 hover:text-white"><Maximize2 className="h-3.5 w-3.5" /></button>
              <button type="button" onClick={resetView} title="Reset graph filters" className="grid h-8 w-8 place-items-center border-l border-white/10 text-zinc-500 hover:bg-white/5 hover:text-white"><RotateCcw className="h-3.5 w-3.5" /></button>
            </div>
            <button type="button" onClick={() => setMobileInspectorOpen(true)} title="Open inspector" className="grid h-8 w-8 place-items-center border border-white/10 text-zinc-500 hover:text-white lg:hidden"><PanelRightOpen className="h-3.5 w-3.5" /></button>
          </div>

          <div className="absolute bottom-3 left-3 z-10 hidden items-center gap-3 border border-white/10 bg-black/70 px-2.5 py-1.5 font-mono text-[9px] text-zinc-500 backdrop-blur sm:flex">
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 bg-slate-500" />Evidence</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 bg-cyan-400" />Analysis</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 bg-amber-400" />Correlation</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 bg-rose-400" />Assessment</span>
          </div>

          {model && (
            <div className="absolute right-3 top-14 z-10 flex items-center gap-2 border border-white/10 bg-black/70 px-2.5 py-1.5 font-mono text-[9px] text-zinc-500 backdrop-blur">
              <Boxes className="h-3 w-3" />
              {visibleNodes.length}/{model.totalEntityCount} loaded
            </div>
          )}

          {model ? (
            <svg ref={svgRef} className="absolute inset-0 h-full w-full touch-none pt-11" role="img" aria-label="Interactive APK threat investigation graph">
              <defs>
                <pattern id="threat-ops-grid" width="28" height="28" patternUnits="userSpaceOnUse">
                  <path d="M 28 0 L 0 0 0 28" fill="none" stroke="rgba(255,255,255,0.035)" strokeWidth="1" />
                </pattern>
                <marker id="threat-ops-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="strokeWidth">
                  <path d="M0,0 L0,8 L8,4 z" fill="context-stroke" />
                </marker>
              </defs>
              <rect x="-100%" y="-100%" width="300%" height="300%" fill="url(#threat-ops-grid)" />
              <g ref={viewportRef}>
                <g>
                  {visibleEdges.map(edge => {
                    const source = model.nodes.find(node => node.id === edge.source)
                    const target = model.nodes.find(node => node.id === edge.target)
                    if (!source || !target) return null
                    const dimmed = focusedNodeIds && (!focusedNodeIds.has(source.id) || !focusedNodeIds.has(target.id))
                    return (
                      <g key={edge.id} opacity={dimmed ? 0.12 : 1}>
                        <path d={edgePath(source, target)} fill="none" stroke={relationshipColors[edge.kind]} strokeWidth="1.4" markerEnd="url(#threat-ops-arrow)" opacity="0.68" />
                        <text x={(source.x + target.x) / 2} y={(source.y + target.y) / 2 - 5} textAnchor="middle" fill="#71717a" fontSize="9" className="pointer-events-none font-mono">{edge.label}</text>
                      </g>
                    )
                  })}
                </g>

                <g>
                  {visibleNodes.map(node => {
                    const style = kindStyles[node.kind]
                    const selected = selectedNodeId === node.id
                    const matched = !searchValue || `${node.label} ${node.subtitle || ''}`.toLowerCase().includes(searchValue)
                    const dimmed = !matched || Boolean(focusedNodeIds && !focusedNodeIds.has(node.id))
                    const expanded = node.kind === 'group' && expandedGroups.has(node.id)
                    return (
                      <g
                        key={node.id}
                        transform={`translate(${node.x}, ${node.y})`}
                        opacity={dimmed ? 0.16 : 1}
                        className="cursor-pointer transition-opacity"
                        onClick={event => { event.stopPropagation(); selectNode(node) }}
                        onDoubleClick={event => { event.stopPropagation(); if (node.kind === 'group') toggleGroup(node.id); else focusNode(node) }}
                        onContextMenu={event => {
                          event.preventDefault()
                          event.stopPropagation()
                          const rect = canvasRef.current?.getBoundingClientRect()
                          if (rect) setContextMenu({ x: event.clientX - rect.left, y: event.clientY - rect.top, nodeId: node.id })
                        }}
                      >
                        <rect x={-node.width / 2} y={-node.height / 2} width={node.width} height={node.height} rx="5" fill={style.fill} stroke={selected ? '#f4f4f5' : style.accent} strokeWidth={selected ? 2.2 : 1.2} />
                        <rect x={-node.width / 2} y={-node.height / 2} width="4" height={node.height} fill={style.accent} />
                        <rect x={-node.width / 2 + 15} y={-13} width="32" height="26" rx="3" fill="#050505" stroke={style.accent} strokeOpacity="0.55" />
                        <NodeGlyph node={node} />
                        <text x={-node.width / 2 + 58} y={node.subtitle ? -5 : 4} fill="#f4f4f5" fontSize={node.kind === 'apk' ? 12 : 11} fontWeight="600" className="pointer-events-none">{shortText(node.label, node.kind === 'apk' ? 24 : 27)}</text>
                        {node.subtitle && <text x={-node.width / 2 + 58} y="13" fill="#71717a" fontSize="8.5" className="pointer-events-none font-mono">{shortText(node.subtitle, 31)}</text>}
                        {node.kind === 'group' && (
                          <>
                            <circle cx={node.width / 2 - 20} cy="0" r="11" fill="#050505" stroke="#52525b" />
                            <text x={node.width / 2 - 20} y="1" fill="#d4d4d8" fontSize="9" textAnchor="middle" dominantBaseline="middle" className="pointer-events-none font-mono">{node.count}</text>
                            <path d={expanded ? `M ${node.width / 2 - 8} -3 l 4 4 l 4 -4` : `M ${node.width / 2 - 7} -4 l 4 4 l -4 4`} fill="none" stroke="#a1a1aa" strokeWidth="1.2" />
                          </>
                        )}
                        {node.severity && <circle cx={node.width / 2 - 9} cy={-node.height / 2 + 9} r="4" fill={node.severity === 'critical' ? '#fb7185' : node.severity === 'high' ? '#fb923c' : node.severity === 'medium' ? '#facc15' : '#4ade80'} />}
                      </g>
                    )
                  })}
                </g>
              </g>
            </svg>
          ) : (
            <div className="absolute inset-0 top-11 grid place-items-center forensic-grid-bg">
              <div className="max-w-lg px-6 text-center">
                <div className="mx-auto mb-5 grid h-16 w-16 place-items-center border border-rose-400/25 bg-rose-400/[0.04]">
                  <Network className="h-7 w-7 text-rose-300/70" />
                </div>
                <h2 className="font-mono text-sm uppercase text-zinc-200">Investigation graph awaiting evidence</h2>
                <p className="mx-auto mt-3 max-w-md text-xs leading-5 text-zinc-500">No analyzed APK is available in the current case set. The workspace will create entities only from ingested analysis artifacts.</p>
                <Link to="/cases" className="mt-5 inline-flex h-9 items-center gap-2 border border-cyan-400/40 bg-cyan-400/[0.07] px-4 font-mono text-[10px] uppercase text-cyan-200 hover:bg-cyan-400/[0.12]">
                  Open Cases <ChevronRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </div>
          )}

          {contextMenu && contextNode && (
            <div
              className="absolute z-40 w-52 border border-white/15 bg-[#101012] py-1 shadow-2xl"
              style={{ left: Math.min(contextMenu.x, (canvasRef.current?.clientWidth || 240) - 220), top: Math.min(contextMenu.y, (canvasRef.current?.clientHeight || 260) - 190) }}
              onClick={event => event.stopPropagation()}
            >
              <div className="border-b border-white/[0.07] px-3 py-2">
                <p className="truncate text-xs font-medium text-zinc-200">{contextNode.label}</p>
                <p className="mt-0.5 font-mono text-[9px] uppercase text-zinc-600">Investigation pivot</p>
              </div>
              <button type="button" onClick={() => { selectNode(contextNode); setContextMenu(null) }} className="flex h-8 w-full items-center gap-2 px-3 text-left text-[11px] text-zinc-400 hover:bg-white/5 hover:text-white"><ListFilter className="h-3.5 w-3.5" />Inspect evidence</button>
              <button type="button" onClick={() => { focusNode(contextNode); setContextMenu(null) }} className="flex h-8 w-full items-center gap-2 px-3 text-left text-[11px] text-zinc-400 hover:bg-white/5 hover:text-white"><Focus className="h-3.5 w-3.5" />Focus relationships</button>
              {contextNode.kind === 'group' && (
                <button type="button" onClick={() => { toggleGroup(contextNode.id); setContextMenu(null) }} className="flex h-8 w-full items-center gap-2 px-3 text-left text-[11px] text-zinc-400 hover:bg-white/5 hover:text-white"><Layers3 className="h-3.5 w-3.5" />{expandedGroups.has(contextNode.id) ? 'Collapse entities' : 'Expand entities'}</button>
              )}
              {contextNode.kind === 'group' && expandedGroups.has(contextNode.id) && (contextNode.loadedCount || 0) < (contextNode.count || 0) && (
                <button type="button" onClick={() => { loadMore(contextNode.id); setContextMenu(null) }} className="flex h-8 w-full items-center gap-2 px-3 text-left text-[11px] text-zinc-400 hover:bg-white/5 hover:text-white"><MoreHorizontal className="h-3.5 w-3.5" />Load next {PAGE_SIZE}</button>
              )}
              {contextNode.kind !== 'apk' && (
                <button type="button" onClick={() => { setHiddenNodeIds(current => new Set([...current, contextNode.id])); setContextMenu(null) }} className="flex h-8 w-full items-center gap-2 px-3 text-left text-[11px] text-zinc-400 hover:bg-white/5 hover:text-white"><X className="h-3.5 w-3.5" />Hide from view</button>
              )}
            </div>
          )}
        </main>

        <div className="hidden min-h-0 lg:block">
          <Inspector tab={inspectorTab} onTabChange={setInspectorTab} node={selectedNode} stage={selectedStage} relationships={relationships} narrative={narrative} />
        </div>

        {mobileInspectorOpen && (
          <div className="absolute inset-0 z-50 bg-black/65 lg:hidden" onClick={() => setMobileInspectorOpen(false)}>
            <div className="absolute inset-y-0 right-0 w-[min(92vw,380px)]" onClick={event => event.stopPropagation()}>
              <Inspector tab={inspectorTab} onTabChange={setInspectorTab} node={selectedNode} stage={selectedStage} relationships={relationships} narrative={narrative} onClose={() => setMobileInspectorOpen(false)} />
            </div>
          </div>
        )}
      </div>

      <Timeline evidence={evidence} stages={stages} onStageSelect={selectStage} />
    </div>
  )
}

export default ThreatInvestigationWorkspace
