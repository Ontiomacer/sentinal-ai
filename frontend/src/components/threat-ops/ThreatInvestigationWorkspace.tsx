import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Boxes,
  ChevronDown,
  ChevronRight,
  CircleDot,
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
  extractInvestigationEvidence,
  extractThreatNarrative,
  InvestigationEvidenceSummary,
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

// Right-panel tabs
type RightTab = 'overview' | 'evidence' | 'narrative' | 'timeline'

const PAGE_SIZE = 18

// ─── Visual constants ─────────────────────────────────────────────────────────

const kindStyles: Record<InvestigationNodeKind, { accent: string; fill: string; code: string }> = {
  apk:            { accent: '#22d3ee', fill: '#06252b', code: 'APK' },
  group:          { accent: '#a3a3a3', fill: '#171717', code: 'SET' },
  manifest:       { accent: '#c084fc', fill: '#21142d', code: 'MF'  },
  permission:     { accent: '#34d399', fill: '#0b251d', code: 'PM'  },
  activity:       { accent: '#60a5fa', fill: '#0d1e35', code: 'AC'  },
  service:        { accent: '#38bdf8', fill: '#0b2230', code: 'SV'  },
  receiver:       { accent: '#818cf8', fill: '#171a36', code: 'RC'  },
  provider:       { accent: '#a78bfa', fill: '#1d1734', code: 'PV'  },
  string:         { accent: '#d4d4d8', fill: '#1c1c1f', code: 'ST'  },
  certificate:    { accent: '#facc15', fill: '#2b2508', code: 'CRT' },
  sdk:            { accent: '#67e8f9', fill: '#0b2730', code: 'SDK' },
  domain:         { accent: '#fbbf24', fill: '#2a1d07', code: 'DM'  },
  url:            { accent: '#fb923c', fill: '#2b1508', code: 'URL' },
  ip:             { accent: '#f97316', fill: '#2a1208', code: 'IP'  },
  finding:        { accent: '#fb7185', fill: '#301018', code: 'FD'  },
  ioc:            { accent: '#f59e0b', fill: '#291a05', code: 'IOC' },
  risk:           { accent: '#f43f5e', fill: '#310c15', code: 'RSK' },
  recommendation: { accent: '#a3e635', fill: '#172407', code: 'ACT' },
  function:       { accent: '#2dd4bf', fill: '#072823', code: 'FN'  },
  library:        { accent: '#94a3b8', fill: '#17202a', code: 'LIB' },
}

const relationshipColors: Record<RelationshipKind, string> = {
  evidence:    '#64748b',
  analysis:    '#22d3ee',
  correlation: '#f59e0b',
  assessment:  '#fb7185',
}

const statusStyles: Record<WorkflowStatus, { label: string; color: string }> = {
  completed: { label: 'Done',    color: '#4ade80' },
  running:   { label: 'Running', color: '#22d3ee' },
  failed:    { label: 'Failed',  color: '#fb7185' },
  pending:   { label: 'Pending', color: '#52525b' },
}

const severityClasses: Record<Severity, string> = {
  critical: 'border-rose-400/50 bg-rose-400/10 text-rose-300',
  high:     'border-orange-400/50 bg-orange-400/10 text-orange-300',
  medium:   'border-amber-300/50 bg-amber-300/10 text-amber-200',
  low:      'border-emerald-400/50 bg-emerald-400/10 text-emerald-300',
  info:     'border-zinc-500/50 bg-zinc-500/10 text-zinc-300',
}

// ─── Pure helpers ─────────────────────────────────────────────────────────────

const clampConfidence = (v: number) => Math.max(0, Math.min(100, v <= 1 ? v * 100 : v))

const edgePath = (source: InvestigationNode, target: InvestigationNode): string => {
  const sx = source.x + source.width / 2
  const tx = target.x - target.width / 2
  const cp = Math.max(80, (tx - sx) * 0.45)
  return `M ${sx} ${source.y} C ${sx + cp} ${source.y}, ${tx - cp} ${target.y}, ${tx} ${target.y}`
}

const shortText = (v: string, max: number) => v.length > max ? `${v.slice(0, max - 3)}…` : v

// ─── Micro components ─────────────────────────────────────────────────────────

const SectionTitle = ({ children }: { children: string }) => (
  <div className="mb-3 flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-zinc-500">
    <span className="h-px w-3 bg-zinc-700" />
    {children}
  </div>
)

const EmptyValue = ({ children }: { children: string }) => (
  <p className="font-mono text-[11px] leading-5 text-zinc-600 italic">{children}</p>
)

const evidenceLabel = (value: unknown): string => {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (typeof value !== 'object' || value === null) return ''
  const item = value as Record<string, unknown>
  for (const key of ['name', 'value', 'sha256', 'subject', 'description', 'exception_message']) {
    if (typeof item[key] === 'string' && item[key]) return item[key] as string
  }
  return Object.entries(item)
    .filter(([, f]) => typeof f === 'string' || typeof f === 'number' || typeof f === 'boolean')
    .slice(0, 3)
    .map(([k, f]) => `${k}: ${String(f)}`)
    .join(' · ')
}

const EvidenceList = ({ values, empty }: { values: unknown[]; empty: string }) =>
  values.length ? (
    <ul className="space-y-2 font-mono text-[10px] leading-4 text-zinc-300">
      {values.map((v, i) => (
        <li key={`${evidenceLabel(v)}-${i}`} className="break-words border-l-2 border-cyan-400/25 pl-3">
          {evidenceLabel(v)}
        </li>
      ))}
    </ul>
  ) : <EmptyValue>{empty}</EmptyValue>

// ─── Graph node glyph ─────────────────────────────────────────────────────────

const NodeGlyph = ({ node }: { node: InvestigationNode }) => {
  const s = kindStyles[node.kind]
  return (
    <text
      x={-node.width / 2 + 33}
      y={node.kind === 'apk' ? 2 : 1}
      fill={s.accent}
      fontSize={s.code.length > 2 ? 8 : 9}
      fontWeight="700"
      textAnchor="middle"
      dominantBaseline="middle"
      className="pointer-events-none font-mono"
    >
      {s.code}
    </text>
  )
}

// ─── Pipeline strip (compact, collapsed by default) ───────────────────────────

const PipelineStrip = ({
  stages,
  selectedStageId,
  onSelect,
}: {
  stages: WorkflowStage[]
  selectedStageId: string | null
  onSelect: (stage: WorkflowStage) => void
}) => {
  const [expanded, setExpanded] = useState(false)
  const completed = stages.filter(s => s.status === 'completed').length
  const running   = stages.find(s => s.status === 'running')
  const failed    = stages.find(s => s.status === 'failed')
  const statusColor = failed ? '#fb7185' : running ? '#22d3ee' : completed === stages.length ? '#4ade80' : '#52525b'

  return (
    <div className="shrink-0 border-b border-white/[0.07] bg-[#09090b]">
      {/* Collapsed bar */}
      <button
        type="button"
        onClick={() => setExpanded(e => !e)}
        className="flex h-9 w-full items-center gap-3 px-4 text-left hover:bg-white/[0.02]"
        aria-expanded={expanded}
      >
        {/* Stage dots */}
        <div className="flex items-center gap-1">
          {stages.map(s => (
            <span
              key={s.id}
              className={`h-1.5 w-1.5 rounded-full ${s.status === 'running' ? 'animate-pulse' : ''}`}
              style={{ background: statusStyles[s.status].color }}
              title={s.label}
            />
          ))}
        </div>
        <span className="font-mono text-[10px] text-zinc-500">
          {failed
            ? `Failed at ${failed.label}`
            : running
              ? `Running — ${running.label}`
              : `${completed}/${stages.length} stages complete`}
        </span>
        <span className="ml-auto flex items-center gap-1.5 font-mono text-[9px] uppercase text-zinc-600">
          Pipeline
          <ChevronDown className={`h-3 w-3 transition-transform ${expanded ? 'rotate-180' : ''}`} />
        </span>
      </button>

      {/* Expanded detail drawer */}
      {expanded && (
        <div className="border-t border-white/[0.06] px-4 py-3">
          <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3 md:grid-cols-5 lg:grid-cols-10">
            {stages.map(s => {
              const st = statusStyles[s.status]
              const sel = selectedStageId === s.id
              return (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => onSelect(s)}
                  className={`group relative rounded border px-2 py-2 text-left transition-colors ${
                    sel
                      ? 'border-cyan-300/50 bg-cyan-300/[0.06]'
                      : 'border-white/[0.07] bg-white/[0.02] hover:border-white/20'
                  }`}
                >
                  <span
                    className={`mb-1.5 block h-1 w-full rounded-full ${s.status === 'running' ? 'animate-pulse' : ''}`}
                    style={{ background: st.color }}
                  />
                  <span className="block truncate font-mono text-[9px] text-zinc-300">{s.label}</span>
                  <span className="block truncate font-mono text-[8px]" style={{ color: st.color }}>{st.label}</span>
                  {s.durationMs !== undefined && (
                    <span className="block font-mono text-[8px] text-zinc-700">
                      {s.durationMs < 1000 ? `${s.durationMs}ms` : `${(s.durationMs / 1000).toFixed(1)}s`}
                    </span>
                  )}
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Stage detail (shown in right panel when stage selected) ──────────────────

const StageDetail = ({ stage }: { stage: WorkflowStage }) => (
  <div className="divide-y divide-white/[0.06] py-2">
    <div className="px-5 py-4">
      <div className="mb-1.5 flex items-center justify-between gap-3">
        <span className="font-mono text-[10px] uppercase text-cyan-400">{stage.agent}</span>
        <span className="rounded border px-2 py-0.5 font-mono text-[9px] uppercase"
          style={{ borderColor: statusStyles[stage.status].color, color: statusStyles[stage.status].color }}>
          {statusStyles[stage.status].label}
        </span>
      </div>
      <h2 className="text-[15px] font-semibold leading-6 text-white">{stage.label}</h2>
    </div>
    <div className="px-5 py-4">
      <SectionTitle>Purpose</SectionTitle>
      <p className="text-[12px] leading-6 text-zinc-300">{stage.purpose}</p>
    </div>
    <div className="grid grid-cols-2 divide-x divide-white/[0.06] px-5 py-4">
      <div className="pr-4">
        <SectionTitle>Input</SectionTitle>
        <p className="font-mono text-[11px] text-zinc-300">{stage.input}</p>
      </div>
      <div className="pl-4">
        <SectionTitle>Output</SectionTitle>
        <p className="font-mono text-[11px] text-zinc-300">{stage.output}</p>
      </div>
    </div>
    <div className="px-5 py-4">
      <SectionTitle>Execution</SectionTitle>
      <dl className="grid grid-cols-[76px_minmax(0,1fr)] gap-x-4 gap-y-2.5 font-mono text-[11px]">
        <dt className="text-zinc-600">Started</dt>
        <dd className="text-zinc-300">{stage.startedAt ? new Date(stage.startedAt).toLocaleString() : 'Pending'}</dd>
        <dt className="text-zinc-600">Finished</dt>
        <dd className="text-zinc-300">{stage.finishedAt ? new Date(stage.finishedAt).toLocaleString() : '—'}</dd>
        <dt className="text-zinc-600">Duration</dt>
        <dd className="text-zinc-300">{stage.durationMs == null ? '—' : `${stage.durationMs} ms`}</dd>
      </dl>
    </div>
    {stage.error && (
      <div className="border-l-2 border-rose-400 bg-rose-400/[0.04] px-5 py-4">
        <SectionTitle>Exact Failure</SectionTitle>
        <p className="font-mono text-[11px] text-rose-300">{stage.error.exceptionType}: {stage.error.exceptionMessage}</p>
        {stage.error.traceback && (
          <pre className="mt-3 max-h-56 overflow-auto whitespace-pre-wrap break-words font-mono text-[9px] leading-4 text-zinc-500">
            {stage.error.traceback}
          </pre>
        )}
      </div>
    )}
  </div>
)

// ─── Node detail (shown in right panel when node selected) ────────────────────

const NodeDetail = ({
  node,
  relationships,
}: {
  node: InvestigationNode
  relationships: Array<{ edge: InvestigationEdge; node: InvestigationNode }>
}) => (
  <div className="divide-y divide-white/[0.06] py-2">
    <div className="px-5 py-4">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <span className="font-mono text-[10px] uppercase" style={{ color: kindStyles[node.kind].accent }}>
          {node.kind}
        </span>
        {node.severity && (
          <span className={`rounded border px-1.5 py-0.5 font-mono text-[9px] uppercase ${severityClasses[node.severity]}`}>
            {node.severity}
          </span>
        )}
      </div>
      <h2 className="break-words text-[15px] font-semibold leading-6 text-white">{node.label}</h2>
      {node.subtitle && <p className="mt-1 break-words font-mono text-[10px] text-zinc-500">{node.subtitle}</p>}
    </div>

    <div className="px-5 py-4">
      <SectionTitle>Purpose</SectionTitle>
      <p className="text-[12px] leading-6 text-zinc-300">{node.purpose}</p>
    </div>

    <div className="px-5 py-4">
      <SectionTitle>Evidence</SectionTitle>
      {node.evidence.length ? (
        <ul className="space-y-2 font-mono text-[11px] leading-5 text-zinc-300">
          {node.evidence.map((e, i) => (
            <li key={`${e}-${i}`} className="break-words border-l-2 border-cyan-400/30 pl-3">{e}</li>
          ))}
        </ul>
      ) : <EmptyValue>No evidence attached to this artifact.</EmptyValue>}
    </div>

    <div className="px-5 py-4">
      <SectionTitle>Relationships</SectionTitle>
      {relationships.length ? (
        <ul className="space-y-2">
          {relationships.map(({ edge, node: rn }) => (
            <li key={edge.id} className="flex items-start justify-between gap-3 text-[11px]">
              <span className="min-w-0 break-words text-zinc-300">{rn.label}</span>
              <span className="shrink-0 font-mono text-[9px] text-zinc-600">{edge.label}</span>
            </li>
          ))}
        </ul>
      ) : <EmptyValue>No visible relationships for this artifact.</EmptyValue>}
    </div>

    {node.reasoning && (
      <div className="px-5 py-4">
        <SectionTitle>Reasoning</SectionTitle>
        <p className="text-[12px] leading-6 text-zinc-300">{node.reasoning}</p>
      </div>
    )}

    {(node.riskScore !== undefined || node.confidence !== undefined || node.riskImpact) && (
      <div className="px-5 py-4">
        <SectionTitle>Risk Impact & Confidence</SectionTitle>
        {node.riskImpact && <p className="mb-3 text-[12px] leading-6 text-zinc-300">{node.riskImpact}</p>}
        <div className="space-y-3">
          {node.riskScore !== undefined && (
            <div>
              <div className="mb-1.5 flex justify-between font-mono text-[10px] text-zinc-500">
                <span>Risk score</span><span>{node.riskScore}/100</span>
              </div>
              <div className="h-1.5 rounded bg-zinc-900">
                <div className="h-full rounded bg-rose-400" style={{ width: `${Math.max(0, Math.min(100, node.riskScore))}%` }} />
              </div>
            </div>
          )}
          {node.confidence !== undefined && (
            <div>
              <div className="mb-1.5 flex justify-between font-mono text-[10px] text-zinc-500">
                <span>Confidence</span><span>{Math.round(clampConfidence(node.confidence))}%</span>
              </div>
              <div className="h-1.5 rounded bg-zinc-900">
                <div className="h-full rounded bg-cyan-400" style={{ width: `${clampConfidence(node.confidence)}%` }} />
              </div>
            </div>
          )}
        </div>
      </div>
    )}

    {node.recommendations.length > 0 && (
      <div className="px-5 py-4">
        <SectionTitle>Recommendations</SectionTitle>
        <ul className="space-y-2 text-[12px] leading-6 text-zinc-300">
          {node.recommendations.map((r, i) => <li key={`${r}-${i}`}>{i + 1}. {r}</li>)}
        </ul>
      </div>
    )}

    {node.artifacts.length > 0 && (
      <div className="px-5 py-4">
        <SectionTitle>Supporting Artifacts</SectionTitle>
        <dl className="divide-y divide-white/[0.05]">
          {node.artifacts.map(a => (
            <div key={`${a.label}-${a.value}`} className="grid grid-cols-[96px_minmax(0,1fr)] gap-3 py-2.5 font-mono text-[11px]">
              <dt className="text-zinc-600">{a.label}</dt>
              <dd className="break-words text-zinc-300">{a.value}</dd>
            </div>
          ))}
        </dl>
      </div>
    )}
  </div>
)

// ─── Overview tab ─────────────────────────────────────────────────────────────

const OverviewTab = ({
  narrative,
  evidenceSummary,
}: {
  narrative: ThreatNarrative
  evidenceSummary: InvestigationEvidenceSummary
}) => (
  <div className="divide-y divide-white/[0.06]">
    {/* Risk score hero */}
    {(narrative.riskScore !== undefined || narrative.severity) && (
      <div className="flex items-center gap-6 px-5 py-5">
        <div className="grid h-14 w-14 shrink-0 place-items-center rounded border border-rose-400/30 bg-rose-400/[0.07]">
          <span className="text-xl font-bold text-rose-300">{narrative.riskScore ?? '—'}</span>
        </div>
        <div>
          <div className="font-mono text-[9px] uppercase text-zinc-600">Static Risk Score</div>
          <div className="mt-0.5 font-mono text-sm uppercase tracking-wide text-zinc-200">
            {narrative.severity ?? 'Unknown severity'}
          </div>
          {narrative.confidence !== undefined && (
            <div className="mt-0.5 font-mono text-[10px] text-zinc-500">
              Confidence {narrative.confidence}%
            </div>
          )}
        </div>
      </div>
    )}

    {/* Executive summary */}
    <div className="px-5 py-5">
      <SectionTitle>Executive Summary</SectionTitle>
      {narrative.executiveSummary
        ? <p className="text-[12px] leading-6 text-zinc-300">{narrative.executiveSummary}</p>
        : <EmptyValue>No executive summary available. Run the investigation to generate one.</EmptyValue>}
    </div>

    {/* Key findings */}
    {narrative.keyFindings.length > 0 && (
      <div className="px-5 py-5">
        <SectionTitle>Key Findings</SectionTitle>
        <ul className="space-y-3">
          {narrative.keyFindings.map((f, i) => (
            <li key={`${f}-${i}`} className="flex gap-3 text-[12px] leading-6 text-zinc-300">
              <CircleDot className="mt-1 h-3.5 w-3.5 shrink-0 text-rose-400" />
              <span>{f}</span>
            </li>
          ))}
        </ul>
      </div>
    )}

    {/* Package identity quick-ref */}
    {(evidenceSummary.packageName || evidenceSummary.sha256) && (
      <div className="px-5 py-5">
        <SectionTitle>Package Identity</SectionTitle>
        <dl className="space-y-2.5 font-mono text-[11px]">
          {evidenceSummary.packageName && (
            <div>
              <dt className="mb-0.5 text-zinc-600">Package</dt>
              <dd className="break-all text-zinc-300">{evidenceSummary.packageName}</dd>
            </div>
          )}
          {evidenceSummary.sha256 && (
            <div>
              <dt className="mb-0.5 text-zinc-600">SHA-256</dt>
              <dd className="break-all text-zinc-400">{evidenceSummary.sha256}</dd>
            </div>
          )}
        </dl>
      </div>
    )}
  </div>
)

// ─── Evidence tab ─────────────────────────────────────────────────────────────

const EvidenceTab = ({ evidence }: { evidence: InvestigationEvidenceSummary }) => (
  <div className="divide-y divide-white/[0.06]">
    <div className="px-5 py-5">
      <SectionTitle>Package Identity</SectionTitle>
      <dl className="space-y-2.5 font-mono text-[11px]">
        <div>
          <dt className="mb-0.5 text-zinc-600">Package</dt>
          <dd className="break-words text-zinc-300">{evidence.packageName || 'Not yet extracted'}</dd>
        </div>
        <div>
          <dt className="mb-0.5 text-zinc-600">SHA-256</dt>
          <dd className="break-all text-zinc-400">{evidence.sha256 || 'Not yet verified'}</dd>
        </div>
      </dl>
    </div>
    <div className="px-5 py-5">
      <SectionTitle>Permissions</SectionTitle>
      <EvidenceList values={evidence.permissions} empty="No permissions extracted." />
    </div>
    <div className="px-5 py-5">
      <SectionTitle>Certificates</SectionTitle>
      <EvidenceList values={evidence.certificates} empty="No certificates extracted." />
    </div>
    <div className="px-5 py-5">
      <SectionTitle>Suspicious Indicators</SectionTitle>
      <EvidenceList values={evidence.suspiciousIndicators} empty="No suspicious indicators matched." />
    </div>
    <div className="px-5 py-5">
      <SectionTitle>Extracted URLs</SectionTitle>
      <EvidenceList values={evidence.urls} empty="No URLs extracted." />
    </div>
    <div className="px-5 py-5">
      <SectionTitle>Extracted Domains</SectionTitle>
      <EvidenceList values={evidence.domains} empty="No domains extracted." />
    </div>
    <div className="px-5 py-5">
      <SectionTitle>Extracted IPs</SectionTitle>
      <EvidenceList values={evidence.ips} empty="No IP addresses extracted." />
    </div>
  </div>
)

// ─── Narrative tab ────────────────────────────────────────────────────────────

const NarrativeTab = ({ narrative }: { narrative: ThreatNarrative }) => (
  <div className="divide-y divide-white/[0.06]">
    <div className="px-5 py-5">
      <SectionTitle>Executive Summary</SectionTitle>
      {narrative.executiveSummary
        ? <p className="text-[12px] leading-6 text-zinc-300">{narrative.executiveSummary}</p>
        : <EmptyValue>No executive summary was returned by this analysis.</EmptyValue>}
    </div>

    {(narrative.riskScore !== undefined || narrative.severity) && (
      <div className="grid grid-cols-2 divide-x divide-white/[0.06] px-5 py-4 text-center">
        <div className="pr-4">
          <div className="mb-1 font-mono text-[9px] uppercase text-zinc-600">Risk Score</div>
          <div className="text-lg font-semibold text-rose-300">{narrative.riskScore ?? '—'}</div>
        </div>
        <div className="pl-4">
          <div className="mb-1 font-mono text-[9px] uppercase text-zinc-600">Severity</div>
          <div className="mt-1 font-mono text-[11px] uppercase text-zinc-300">{narrative.severity || '—'}</div>
        </div>
      </div>
    )}

    <div className="px-5 py-5">
      <SectionTitle>Key Findings</SectionTitle>
      {narrative.keyFindings.length ? (
        <ul className="space-y-3">
          {narrative.keyFindings.map((f, i) => (
            <li key={`${f}-${i}`} className="flex gap-3 text-[12px] leading-6 text-zinc-300">
              <CircleDot className="mt-1 h-3.5 w-3.5 shrink-0 text-rose-400" />
              <span>{f}</span>
            </li>
          ))}
        </ul>
      ) : <EmptyValue>No key findings were returned by this analysis.</EmptyValue>}
    </div>

    <div className="px-5 py-5">
      <SectionTitle>Threat Assessment</SectionTitle>
      {narrative.threatAssessment
        ? <p className="text-[12px] leading-6 text-zinc-300">{narrative.threatAssessment}</p>
        : <EmptyValue>No threat assessment narrative was returned.</EmptyValue>}
    </div>

    <div className="px-5 py-5">
      <SectionTitle>Risk Score Explanation</SectionTitle>
      {narrative.riskExplanation
        ? <p className="text-[12px] leading-6 text-zinc-300">{narrative.riskExplanation}</p>
        : <EmptyValue>No score explanation was returned by this analysis.</EmptyValue>}
    </div>

    {narrative.scoreCalculation.length > 0 && (
      <div className="px-5 py-5">
        <SectionTitle>Exact Score Calculation</SectionTitle>
        <div className="divide-y divide-white/[0.05] rounded border border-white/[0.07]">
          {narrative.scoreCalculation.map(item => (
            <div key={item.factor} className="px-4 py-3">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-[12px] font-medium text-zinc-200">{item.factor}</p>
                  <p className="mt-0.5 font-mono text-[9px] text-zinc-600">{item.formula} · count {item.count}</p>
                </div>
                <span className="font-mono text-[12px] text-rose-300">+{item.points}</span>
              </div>
              {item.evidence.length > 0 && (
                <p className="mt-2 break-words font-mono text-[9px] leading-4 text-zinc-500">{item.evidence.join(', ')}</p>
              )}
            </div>
          ))}
        </div>
      </div>
    )}

    <div className="px-5 py-5">
      <SectionTitle>Recommended Actions</SectionTitle>
      {narrative.recommendedActions.length ? (
        <ul className="space-y-3">
          {narrative.recommendedActions.map((a, i) => (
            <li key={`${a}-${i}`} className="flex gap-3 text-[12px] leading-6 text-zinc-300">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-lime-400" />
              <span>{a}</span>
            </li>
          ))}
        </ul>
      ) : <EmptyValue>No recommended actions were returned by this analysis.</EmptyValue>}
    </div>
  </div>
)

// ─── Timeline tab (full detail list) ─────────────────────────────────────────

const TimelineTab = ({
  evidence,
  stages,
  onStageSelect,
}: {
  evidence: Evidence | null
  stages: WorkflowStage[]
  onStageSelect: (stage: WorkflowStage) => void
}) => {
  const events = evidence
    ? [
        {
          id: 'imported',
          label: 'APK Imported',
          status: 'completed' as WorkflowStatus,
          startedAt: evidence.created_at,
          finishedAt: undefined as string | undefined,
          durationMs: undefined as number | undefined,
          isStage: false,
        },
        ...stages.map(s => ({
          id: s.id,
          label: s.label,
          status: s.status,
          startedAt: s.startedAt,
          finishedAt: s.finishedAt,
          durationMs: s.durationMs,
          isStage: true,
        })),
      ]
    : stages.map(s => ({
        id: s.id,
        label: s.label,
        status: s.status,
        startedAt: s.startedAt,
        finishedAt: s.finishedAt,
        durationMs: s.durationMs,
        isStage: true,
      }))

  return (
    <div className="px-5 py-5">
      <SectionTitle>Investigation Timeline</SectionTitle>
      <ol className="relative border-l border-white/10">
        {events.map(ev => {
          const st = statusStyles[ev.status]
          return (
            <li key={ev.id} className="mb-5 ml-4">
              <span
                className={`absolute -left-[7px] mt-1 h-3.5 w-3.5 rounded-full border-2 border-[#09090b] ${ev.status === 'running' ? 'animate-pulse' : ''}`}
                style={{ background: st.color }}
              />
              <button
                type="button"
                disabled={!ev.isStage}
                onClick={() => {
                  const stage = stages.find(s => s.id === ev.id)
                  if (stage) onStageSelect(stage)
                }}
                className="text-left disabled:cursor-default"
              >
                <p className="font-mono text-[11px] font-semibold text-zinc-200 hover:text-cyan-300 disabled:hover:text-zinc-200">
                  {ev.label}
                </p>
                <p className="mt-0.5 font-mono text-[10px]" style={{ color: st.color }}>{st.label}</p>
                {ev.startedAt && (
                  <p className="mt-0.5 font-mono text-[9px] text-zinc-600">
                    {new Date(ev.startedAt).toLocaleTimeString()}
                    {ev.finishedAt && ` → ${new Date(ev.finishedAt).toLocaleTimeString()}`}
                    {ev.durationMs !== undefined && ` · ${ev.durationMs < 1000 ? `${ev.durationMs}ms` : `${(ev.durationMs / 1000).toFixed(1)}s`}`}
                  </p>
                )}
              </button>
            </li>
          )
        })}
      </ol>
    </div>
  )
}

// ─── Right panel ──────────────────────────────────────────────────────────────

interface RightPanelProps {
  tab: RightTab
  onTabChange: (tab: RightTab) => void
  selectedNode: InvestigationNode | null
  selectedStage: WorkflowStage | null
  relationships: Array<{ edge: InvestigationEdge; node: InvestigationNode }>
  narrative: ThreatNarrative
  evidenceSummary: InvestigationEvidenceSummary
  evidence: Evidence | null
  stages: WorkflowStage[]
  onStageSelect: (stage: WorkflowStage) => void
  onClose?: () => void
}

const TABS: { id: RightTab; label: string }[] = [
  { id: 'overview',  label: 'Overview'  },
  { id: 'evidence',  label: 'Evidence'  },
  { id: 'narrative', label: 'Narrative' },
  { id: 'timeline',  label: 'Timeline'  },
]

const RightPanel = ({
  tab,
  onTabChange,
  selectedNode,
  selectedStage,
  relationships,
  narrative,
  evidenceSummary,
  evidence,
  stages,
  onStageSelect,
  onClose,
}: RightPanelProps) => (
  <aside className="flex h-full min-h-0 flex-col border-l border-white/[0.08] bg-[#09090b]">
    {/* Tab bar */}
    <div className="flex h-11 shrink-0 items-center justify-between border-b border-white/[0.08] pl-2 pr-2">
      <div className="flex h-full items-end gap-0.5">
        {TABS.map(t => (
          <button
            key={t.id}
            type="button"
            onClick={() => onTabChange(t.id)}
            className={`flex h-9 items-center px-3 font-mono text-[10px] uppercase transition-colors ${
              tab === t.id
                ? 'border-b-2 border-cyan-400 text-cyan-300'
                : 'text-zinc-600 hover:text-zinc-300'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>
      {onClose && (
        <button type="button" onClick={onClose} className="grid h-8 w-8 place-items-center text-zinc-600 hover:text-white">
          <X className="h-4 w-4" />
        </button>
      )}
    </div>

    {/* Scrollable body */}
    <div className="min-h-0 flex-1 overflow-y-auto custom-scrollbar">
      {/* Context: selected stage or node overrides tab content for evidence tab */}
      {selectedStage && tab === 'evidence' ? (
        <StageDetail stage={selectedStage} />
      ) : selectedNode && tab === 'evidence' ? (
        <NodeDetail node={selectedNode} relationships={relationships} />
      ) : tab === 'overview' ? (
        <OverviewTab narrative={narrative} evidenceSummary={evidenceSummary} />
      ) : tab === 'evidence' ? (
        <EvidenceTab evidence={evidenceSummary} />
      ) : tab === 'narrative' ? (
        <NarrativeTab narrative={narrative} />
      ) : (
        <TimelineTab evidence={evidence} stages={stages} onStageSelect={onStageSelect} />
      )}
    </div>
  </aside>
)

// ─── Main workspace ───────────────────────────────────────────────────────────

const ThreatInvestigationWorkspace = ({ evidence, analysisResult }: ThreatInvestigationWorkspaceProps) => {
  const svgRef = useRef<SVGSVGElement>(null)
  const viewportRef = useRef<SVGGElement>(null)
  const canvasRef = useRef<HTMLDivElement>(null)
  const zoomBehaviorRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null)

  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [groupLimits, setGroupLimits]       = useState<Record<string, number>>({})
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [selectedStageId, setSelectedStageId] = useState<string | null>(null)
  const [hiddenNodeIds, setHiddenNodeIds]   = useState<Set<string>>(new Set())
  const [focusNodeId, setFocusNodeId]       = useState<string | null>(null)
  const [search, setSearch]                 = useState('')
  const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all')
  const [relationshipFilter, setRelationshipFilter] = useState<'all' | RelationshipKind>('all')
  const [contextMenu, setContextMenu]       = useState<ContextMenuState | null>(null)
  const [rightTab, setRightTab]             = useState<RightTab>('overview')
  const [mobileInspectorOpen, setMobileInspectorOpen] = useState(false)

  const stages         = useMemo(() => buildWorkflowStages(evidence, analysisResult), [evidence, analysisResult])
  const narrative      = useMemo(() => extractThreatNarrative(analysisResult), [analysisResult])
  const evidenceSummary = useMemo(() => extractInvestigationEvidence(analysisResult), [analysisResult])
  const model          = useMemo<InvestigationGraphModel | null>(() => {
    if (!evidence) return null
    return buildInvestigationGraph(evidence, analysisResult, expandedGroups, groupLimits)
  }, [evidence, analysisResult, expandedGroups, groupLimits])

  // Reset on evidence change
  useEffect(() => {
    setExpandedGroups(new Set(['group:manifest', 'group:findings', 'group:risk']))
    setGroupLimits({})
    setSelectedNodeId(null)
    setSelectedStageId(null)
    setHiddenNodeIds(new Set())
    setFocusNodeId(null)
    setRightTab('overview')
  }, [evidence?.id])

  // Zoom setup
  const fitGraph = useCallback((graphModel = model) => {
    const svg = svgRef.current
    const behavior = zoomBehaviorRef.current
    if (!svg || !behavior || !graphModel) return
    const w = svg.clientWidth, h = svg.clientHeight
    if (!w || !h) return
    const bw = graphModel.bounds.maxX - graphModel.bounds.minX
    const bh = graphModel.bounds.maxY - graphModel.bounds.minY
    const scale = Math.max(0.25, Math.min(1.1, (w - 100) / bw, (h - 80) / bh))
    const tx = (w - bw * scale) / 2 - graphModel.bounds.minX * scale
    const ty = (h - bh * scale) / 2 - graphModel.bounds.minY * scale
    select(svg).transition().duration(280).call(behavior.transform, zoomIdentity.translate(tx, ty).scale(scale))
  }, [model])

  useEffect(() => {
    const svg = svgRef.current, vp = viewportRef.current
    if (!svg || !vp) return
    const b = zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.15, 3])
      .filter(e => !e.ctrlKey || e.type === 'wheel')
      .on('zoom', e => select(vp).attr('transform', e.transform.toString()))
    zoomBehaviorRef.current = b
    select(svg).call(b)
    return () => { select(svg).on('.zoom', null); zoomBehaviorRef.current = null }
  }, [])

  useEffect(() => {
    if (!model) return
    const f = window.requestAnimationFrame(() => fitGraph(model))
    return () => window.cancelAnimationFrame(f)
  }, [evidence?.id, fitGraph, model])

  // Filtered nodes / edges
  const visibleNodes = useMemo(() => {
    if (!model) return []
    return model.nodes.filter(n => {
      if (hiddenNodeIds.has(n.id)) return false
      if (severityFilter !== 'all' && n.kind !== 'apk' && n.kind !== 'group' && n.severity !== severityFilter) return false
      return true
    })
  }, [model, hiddenNodeIds, severityFilter])

  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map(n => n.id)), [visibleNodes])

  const visibleEdges = useMemo(() => {
    if (!model) return []
    return model.edges.filter(e =>
      visibleNodeIds.has(e.source) &&
      visibleNodeIds.has(e.target) &&
      (relationshipFilter === 'all' || e.kind === relationshipFilter)
    )
  }, [model, relationshipFilter, visibleNodeIds])

  const focusedNodeIds = useMemo(() => {
    if (!model || !focusNodeId) return null
    const ids = new Set([focusNodeId])
    model.edges.forEach(e => {
      if (e.source === focusNodeId) ids.add(e.target)
      if (e.target === focusNodeId) ids.add(e.source)
    })
    return ids
  }, [model, focusNodeId])

  const selectedNode  = model?.nodes.find(n => n.id === selectedNodeId) || null
  const selectedStage = stages.find(s => s.id === selectedStageId) || null

  const relationships = useMemo(() => {
    if (!model || !selectedNode) return []
    return model.edges.flatMap(e => {
      if (e.source === selectedNode.id) {
        const n = model.nodes.find(c => c.id === e.target)
        return n ? [{ edge: e, node: n }] : []
      }
      if (e.target === selectedNode.id) {
        const n = model.nodes.find(c => c.id === e.source)
        return n ? [{ edge: e, node: n }] : []
      }
      return []
    })
  }, [model, selectedNode])

  // Actions
  const toggleGroup = (id: string) =>
    setExpandedGroups(cur => { const s = new Set(cur); s.has(id) ? s.delete(id) : s.add(id); return s })

  const loadMore = (id: string) =>
    setGroupLimits(cur => ({ ...cur, [id]: (cur[id] || PAGE_SIZE) + PAGE_SIZE }))

  const selectNode = (node: InvestigationNode) => {
    setSelectedNodeId(node.id)
    setSelectedStageId(null)
    setRightTab('evidence')
    setMobileInspectorOpen(true)
  }

  const selectStage = (stage: WorkflowStage) => {
    setSelectedStageId(stage.id)
    setSelectedNodeId(null)
    setRightTab('evidence')
    setMobileInspectorOpen(true)
  }

  const focusNode = (node: InvestigationNode) => {
    const svg = svgRef.current, b = zoomBehaviorRef.current
    if (!svg || !b) return
    const scale = 1.3
    const x = svg.clientWidth / 2 - node.x * scale
    const y = svg.clientHeight / 2 - node.y * scale
    select(svg).transition().duration(240).call(b.transform, zoomIdentity.translate(x, y).scale(scale))
    setFocusNodeId(node.id)
  }

  const zoomBy = (f: number) => {
    if (svgRef.current && zoomBehaviorRef.current)
      select(svgRef.current).transition().duration(160).call(zoomBehaviorRef.current.scaleBy, f)
  }

  const resetView = () => {
    setHiddenNodeIds(new Set())
    setFocusNodeId(null)
    setSearch('')
    setSeverityFilter('all')
    setRelationshipFilter('all')
    fitGraph()
  }

  const contextNode = contextMenu && model ? model.nodes.find(n => n.id === contextMenu.nodeId) || null : null
  const searchValue = search.trim().toLowerCase()
  const hasGraph = Boolean(model && model.totalEntityCount > 1)

  return (
    <div className="flex h-full min-h-0 flex-col bg-[#060607] text-zinc-200" onClick={() => setContextMenu(null)}>

      {/* ── Compact pipeline strip ───────────────────────────────────────────── */}
      <PipelineStrip stages={stages} selectedStageId={selectedStageId} onSelect={selectStage} />

      {/* ── Main body: graph (primary) + right panel ─────────────────────────── */}
      <div className="relative grid min-h-0 flex-1 grid-cols-1 lg:grid-cols-[minmax(0,1fr)_360px] xl:grid-cols-[minmax(0,1fr)_400px]">

        {/* ── Graph canvas ─────────────────────────────────────────────────── */}
        <main ref={canvasRef} className="relative min-h-0 overflow-hidden bg-[#070709]">

          {/* Graph toolbar */}
          <div className="absolute inset-x-0 top-0 z-20 flex h-12 items-center gap-2 border-b border-white/[0.07] bg-[#09090b]/96 px-3 backdrop-blur">
            <div className="relative min-w-0 flex-1 sm:max-w-[280px]">
              <Search className="absolute left-3 top-3 h-3.5 w-3.5 text-zinc-600" />
              <input
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search entities…"
                aria-label="Search graph entities"
                disabled={!model}
                className="h-9 w-full border border-white/[0.08] bg-black/40 pl-9 pr-3 font-mono text-[11px] text-zinc-200 outline-none placeholder:text-zinc-700 focus:border-cyan-400/40 disabled:opacity-40"
              />
            </div>

            <div className="relative hidden sm:block">
              <Filter className="pointer-events-none absolute left-2.5 top-3 h-3 w-3 text-zinc-600" />
              <select
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value as 'all' | Severity)}
                aria-label="Filter by severity"
                className="h-9 appearance-none border border-white/[0.08] bg-black/40 pl-7 pr-7 font-mono text-[10px] uppercase text-zinc-500 outline-none"
              >
                <option value="all">All severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
              <ChevronDown className="pointer-events-none absolute right-2 top-3 h-3 w-3 text-zinc-600" />
            </div>

            <div className="relative hidden md:block">
              <GitBranch className="pointer-events-none absolute left-2.5 top-3 h-3 w-3 text-zinc-600" />
              <select
                value={relationshipFilter}
                onChange={e => setRelationshipFilter(e.target.value as 'all' | RelationshipKind)}
                aria-label="Filter relationships"
                className="h-9 appearance-none border border-white/[0.08] bg-black/40 pl-7 pr-7 font-mono text-[10px] uppercase text-zinc-500 outline-none"
              >
                <option value="all">All relations</option>
                <option value="evidence">Evidence</option>
                <option value="analysis">Analysis</option>
                <option value="correlation">Correlation</option>
                <option value="assessment">Assessment</option>
              </select>
              <ChevronDown className="pointer-events-none absolute right-2 top-3 h-3 w-3 text-zinc-600" />
            </div>

            <div className="ml-auto flex shrink-0 items-center gap-1">
              <div className="flex items-center border border-white/[0.08] bg-black/30">
                <button type="button" onClick={() => zoomBy(1.25)} title="Zoom in"    className="grid h-9 w-9 place-items-center text-zinc-600 hover:bg-white/5 hover:text-white"><ZoomIn  className="h-3.5 w-3.5" /></button>
                <button type="button" onClick={() => zoomBy(0.8)}  title="Zoom out"   className="grid h-9 w-9 place-items-center border-l border-white/[0.08] text-zinc-600 hover:bg-white/5 hover:text-white"><ZoomOut className="h-3.5 w-3.5" /></button>
                <button type="button" onClick={() => fitGraph()}    title="Fit graph"  className="grid h-9 w-9 place-items-center border-l border-white/[0.08] text-zinc-600 hover:bg-white/5 hover:text-white"><Maximize2 className="h-3.5 w-3.5" /></button>
                <button type="button" onClick={resetView}           title="Reset view" className="grid h-9 w-9 place-items-center border-l border-white/[0.08] text-zinc-600 hover:bg-white/5 hover:text-white"><RotateCcw className="h-3.5 w-3.5" /></button>
              </div>
              <button type="button" onClick={() => setMobileInspectorOpen(true)} title="Open panel" className="grid h-9 w-9 place-items-center border border-white/[0.08] text-zinc-600 hover:text-white lg:hidden">
                <PanelRightOpen className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Entity count badge */}
          {hasGraph && (
            <div className="absolute right-4 top-16 z-10 flex items-center gap-1.5 rounded border border-white/[0.07] bg-black/60 px-2.5 py-1 font-mono text-[9px] text-zinc-600 backdrop-blur">
              <Boxes className="h-3 w-3" />
              {visibleNodes.length}/{model!.totalEntityCount} entities
            </div>
          )}

          {/* Edge legend */}
          <div className="absolute bottom-4 left-4 z-10 hidden items-center gap-4 rounded border border-white/[0.07] bg-black/70 px-3 py-2 font-mono text-[9px] text-zinc-600 backdrop-blur sm:flex">
            <span className="flex items-center gap-1.5"><span className="h-1.5 w-4 bg-slate-500 rounded" />Evidence</span>
            <span className="flex items-center gap-1.5"><span className="h-1.5 w-4 bg-cyan-400 rounded" />Analysis</span>
            <span className="flex items-center gap-1.5"><span className="h-1.5 w-4 bg-amber-400 rounded" />Correlation</span>
            <span className="flex items-center gap-1.5"><span className="h-1.5 w-4 bg-rose-400 rounded" />Assessment</span>
          </div>

          {/* Graph SVG */}
          {hasGraph ? (
            <svg
              ref={svgRef}
              className="absolute inset-0 h-full w-full touch-none pt-12"
              role="img"
              aria-label="Interactive APK threat investigation graph"
            >
              <defs>
                <pattern id="threat-ops-grid" width="32" height="32" patternUnits="userSpaceOnUse">
                  <path d="M 32 0 L 0 0 0 32" fill="none" stroke="rgba(255,255,255,0.028)" strokeWidth="1" />
                </pattern>
                <marker id="threat-ops-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="strokeWidth">
                  <path d="M0,0 L0,8 L8,4 z" fill="context-stroke" />
                </marker>
              </defs>
              <rect x="-100%" y="-100%" width="300%" height="300%" fill="url(#threat-ops-grid)" />
              <g ref={viewportRef}>
                {/* Edges */}
                <g>
                  {visibleEdges.map(edge => {
                    const src = model!.nodes.find(n => n.id === edge.source)
                    const tgt = model!.nodes.find(n => n.id === edge.target)
                    if (!src || !tgt) return null
                    const dimmed = focusedNodeIds && (!focusedNodeIds.has(src.id) || !focusedNodeIds.has(tgt.id))
                    return (
                      <g key={edge.id} opacity={dimmed ? 0.1 : 1}>
                        <path
                          d={edgePath(src, tgt)}
                          fill="none"
                          stroke={relationshipColors[edge.kind]}
                          strokeWidth="1.5"
                          markerEnd="url(#threat-ops-arrow)"
                          opacity="0.65"
                        />
                        <text
                          x={(src.x + tgt.x) / 2}
                          y={(src.y + tgt.y) / 2 - 5}
                          textAnchor="middle"
                          fill="#52525b"
                          fontSize="9"
                          className="pointer-events-none font-mono"
                        >
                          {edge.label}
                        </text>
                      </g>
                    )
                  })}
                </g>

                {/* Nodes */}
                <g>
                  {visibleNodes.map(node => {
                    const style = kindStyles[node.kind]
                    const selected = selectedNodeId === node.id
                    const matched = !searchValue || `${node.label} ${node.subtitle || ''}`.toLowerCase().includes(searchValue)
                    const dimmed = !matched || Boolean(focusedNodeIds && !focusedNodeIds.has(node.id))
                    const expanded = node.kind === 'group' && expandedGroups.has(node.id)
                    // Larger nodes for better readability
                    const nw = node.width + 16
                    const nh = node.height + 8
                    return (
                      <g
                        key={node.id}
                        transform={`translate(${node.x}, ${node.y})`}
                        opacity={dimmed ? 0.14 : 1}
                        className="cursor-pointer transition-opacity"
                        onClick={e => { e.stopPropagation(); selectNode(node) }}
                        onDoubleClick={e => { e.stopPropagation(); node.kind === 'group' ? toggleGroup(node.id) : focusNode(node) }}
                        onContextMenu={e => {
                          e.preventDefault(); e.stopPropagation()
                          const rect = canvasRef.current?.getBoundingClientRect()
                          if (rect) setContextMenu({ x: e.clientX - rect.left, y: e.clientY - rect.top, nodeId: node.id })
                        }}
                      >
                        <rect x={-nw / 2} y={-nh / 2} width={nw} height={nh} rx="6" fill={style.fill} stroke={selected ? '#f4f4f5' : style.accent} strokeWidth={selected ? 2.4 : 1.3} />
                        <rect x={-nw / 2} y={-nh / 2} width="5" height={nh} rx="2" fill={style.accent} />
                        <rect x={-nw / 2 + 16} y={-14} width="34" height="28" rx="4" fill="#050505" stroke={style.accent} strokeOpacity="0.5" />
                        <text
                          x={-nw / 2 + 33}
                          y={node.kind === 'apk' ? 2 : 1}
                          fill={style.accent}
                          fontSize={style.code.length > 2 ? 8 : 9}
                          fontWeight="700"
                          textAnchor="middle"
                          dominantBaseline="middle"
                          className="pointer-events-none font-mono"
                        >{style.code}</text>
                        <text x={-nw / 2 + 62} y={node.subtitle ? -6 : 4} fill="#f4f4f5" fontSize={node.kind === 'apk' ? 13 : 12} fontWeight="600" className="pointer-events-none">
                          {shortText(node.label, node.kind === 'apk' ? 22 : 26)}
                        </text>
                        {node.subtitle && (
                          <text x={-nw / 2 + 62} y="12" fill="#71717a" fontSize="9.5" className="pointer-events-none font-mono">
                            {shortText(node.subtitle, 28)}
                          </text>
                        )}
                        {node.kind === 'group' && (
                          <>
                            <circle cx={nw / 2 - 22} cy="0" r="12" fill="#050505" stroke="#3f3f46" />
                            <text x={nw / 2 - 22} y="1" fill="#d4d4d8" fontSize="9" textAnchor="middle" dominantBaseline="middle" className="pointer-events-none font-mono">{node.count}</text>
                            <path d={expanded ? `M ${nw / 2 - 9} -3 l 4 4 l 4 -4` : `M ${nw / 2 - 8} -4 l 4 4 l -4 4`} fill="none" stroke="#a1a1aa" strokeWidth="1.3" />
                          </>
                        )}
                        {node.severity && (
                          <circle cx={nw / 2 - 10} cy={-nh / 2 + 10} r="5"
                            fill={node.severity === 'critical' ? '#fb7185' : node.severity === 'high' ? '#fb923c' : node.severity === 'medium' ? '#facc15' : '#4ade80'}
                          />
                        )}
                      </g>
                    )
                  })}
                </g>
              </g>
            </svg>
          ) : (
            /* Empty / pre-investigation state */
            <div className="absolute inset-0 top-12 grid place-items-center forensic-grid-bg">
              {evidence ? (
                <div className="max-w-md px-8 text-center">
                  <div className="mx-auto mb-6 grid h-16 w-16 place-items-center rounded border border-cyan-400/20 bg-cyan-400/[0.04]">
                    <Network className="h-7 w-7 text-cyan-300/60" />
                  </div>
                  <h2 className="font-mono text-[13px] uppercase tracking-wide text-zinc-200">Ready to investigate</h2>
                  <p className="mx-auto mt-4 text-[12px] leading-6 text-zinc-500">
                    <span className="font-mono text-zinc-300">{evidence.original_filename}</span> is selected.
                    Hit <span className="font-mono text-cyan-300">Start Investigation</span> in the toolbar to run the
                    full 10-stage analysis pipeline.
                  </p>
                  <div className="mt-5 grid grid-cols-2 gap-2 font-mono text-[10px] text-zinc-600">
                    <div className="rounded border border-white/[0.06] bg-black/30 px-3 py-2.5 text-left">
                      <div className="mb-1 text-zinc-600">SHA-256</div>
                      <div className="break-all text-zinc-400">{evidence.sha256.slice(0, 20)}…</div>
                    </div>
                    <div className="rounded border border-white/[0.06] bg-black/30 px-3 py-2.5 text-left">
                      <div className="mb-1 text-zinc-600">Size</div>
                      <div className="text-zinc-400">{(evidence.file_size / 1024 / 1024).toFixed(2)} MB</div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="max-w-md px-8 text-center">
                  <div className="mx-auto mb-6 grid h-16 w-16 place-items-center rounded border border-rose-400/20 bg-rose-400/[0.04]">
                    <Network className="h-7 w-7 text-rose-300/60" />
                  </div>
                  <h2 className="font-mono text-[13px] uppercase tracking-wide text-zinc-200">No APK evidence available</h2>
                  <p className="mx-auto mt-4 text-[12px] leading-6 text-zinc-500">
                    Upload an APK file to a case to begin threat investigation.
                    The graph, evidence, and narrative panels will populate automatically.
                  </p>
                  <Link
                    to="/cases"
                    className="mt-6 inline-flex h-9 items-center gap-2 rounded border border-cyan-400/30 bg-cyan-400/[0.07] px-4 font-mono text-[10px] uppercase text-cyan-200 hover:bg-cyan-400/[0.12]"
                  >
                    Open Cases <ChevronRight className="h-3.5 w-3.5" />
                  </Link>
                </div>
              )}
            </div>
          )}

          {/* Context menu */}
          {contextMenu && contextNode && (
            <div
              className="absolute z-40 w-52 rounded border border-white/15 bg-[#101012] py-1.5 shadow-2xl"
              style={{ left: Math.min(contextMenu.x, (canvasRef.current?.clientWidth || 240) - 216), top: Math.min(contextMenu.y, (canvasRef.current?.clientHeight || 260) - 180) }}
              onClick={e => e.stopPropagation()}
            >
              <div className="border-b border-white/[0.07] px-3 py-2.5">
                <p className="truncate text-[12px] font-medium text-zinc-200">{contextNode.label}</p>
                <p className="mt-0.5 font-mono text-[9px] uppercase text-zinc-600">Investigation pivot</p>
              </div>
              <button type="button" onClick={() => { selectNode(contextNode); setContextMenu(null) }}   className="flex h-9 w-full items-center gap-2.5 px-3 text-left text-[11px] text-zinc-400 hover:bg-white/5 hover:text-white"><ListFilter className="h-3.5 w-3.5" />Inspect evidence</button>
              <button type="button" onClick={() => { focusNode(contextNode); setContextMenu(null) }}    className="flex h-9 w-full items-center gap-2.5 px-3 text-left text-[11px] text-zinc-400 hover:bg-white/5 hover:text-white"><Focus className="h-3.5 w-3.5" />Focus relationships</button>
              {contextNode.kind === 'group' && (
                <button type="button" onClick={() => { toggleGroup(contextNode.id); setContextMenu(null) }} className="flex h-9 w-full items-center gap-2.5 px-3 text-left text-[11px] text-zinc-400 hover:bg-white/5 hover:text-white"><Layers3 className="h-3.5 w-3.5" />{expandedGroups.has(contextNode.id) ? 'Collapse entities' : 'Expand entities'}</button>
              )}
              {contextNode.kind === 'group' && expandedGroups.has(contextNode.id) && (contextNode.loadedCount || 0) < (contextNode.count || 0) && (
                <button type="button" onClick={() => { loadMore(contextNode.id); setContextMenu(null) }} className="flex h-9 w-full items-center gap-2.5 px-3 text-left text-[11px] text-zinc-400 hover:bg-white/5 hover:text-white"><MoreHorizontal className="h-3.5 w-3.5" />Load next {PAGE_SIZE}</button>
              )}
              {contextNode.kind !== 'apk' && (
                <button type="button" onClick={() => { setHiddenNodeIds(c => new Set([...c, contextNode.id])); setContextMenu(null) }} className="flex h-9 w-full items-center gap-2.5 px-3 text-left text-[11px] text-zinc-400 hover:bg-white/5 hover:text-white"><X className="h-3.5 w-3.5" />Hide from view</button>
              )}
            </div>
          )}
        </main>

        {/* ── Right panel (desktop) ─────────────────────────────────────────── */}
        <div className="hidden min-h-0 lg:block">
          <RightPanel
            tab={rightTab}
            onTabChange={setRightTab}
            selectedNode={selectedNode}
            selectedStage={selectedStage}
            relationships={relationships}
            narrative={narrative}
            evidenceSummary={evidenceSummary}
            evidence={evidence}
            stages={stages}
            onStageSelect={selectStage}
          />
        </div>

        {/* ── Right panel (mobile overlay) ──────────────────────────────────── */}
        {mobileInspectorOpen && (
          <div className="absolute inset-0 z-50 bg-black/70 lg:hidden" onClick={() => setMobileInspectorOpen(false)}>
            <div className="absolute inset-y-0 right-0 w-[min(94vw,400px)]" onClick={e => e.stopPropagation()}>
              <RightPanel
                tab={rightTab}
                onTabChange={setRightTab}
                selectedNode={selectedNode}
                selectedStage={selectedStage}
                relationships={relationships}
                narrative={narrative}
                evidenceSummary={evidenceSummary}
                evidence={evidence}
                stages={stages}
                onStageSelect={selectStage}
                onClose={() => setMobileInspectorOpen(false)}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default ThreatInvestigationWorkspace
