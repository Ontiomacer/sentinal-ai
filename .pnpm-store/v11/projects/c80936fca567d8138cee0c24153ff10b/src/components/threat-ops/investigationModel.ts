import { Evidence } from '../../services/caseApi'

export type InvestigationNodeKind =
  | 'apk'
  | 'manifest'
  | 'permission'
  | 'activity'
  | 'service'
  | 'receiver'
  | 'provider'
  | 'string'
  | 'certificate'
  | 'domain'
  | 'url'
  | 'ip'
  | 'finding'
  | 'ioc'
  | 'risk'
  | 'recommendation'
  | 'function'
  | 'library'
  | 'group'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type WorkflowStatus = 'completed' | 'running' | 'failed' | 'pending'
export type RelationshipKind = 'evidence' | 'analysis' | 'correlation' | 'assessment'

export interface InvestigationNode {
  id: string
  label: string
  subtitle?: string
  kind: InvestigationNodeKind
  x: number
  y: number
  width: number
  height: number
  groupId?: string
  count?: number
  loadedCount?: number
  expandable?: boolean
  severity?: Severity
  riskScore?: number
  confidence?: number
  purpose: string
  evidence: string[]
  reasoning?: string
  riskImpact?: string
  recommendations: string[]
  artifacts: Array<{ label: string; value: string }>
  raw: unknown
}

export interface InvestigationEdge {
  id: string
  source: string
  target: string
  label: string
  kind: RelationshipKind
}

export interface InvestigationGraphModel {
  nodes: InvestigationNode[]
  edges: InvestigationEdge[]
  totalEntityCount: number
  bounds: { minX: number; minY: number; maxX: number; maxY: number }
}

export interface WorkflowStage {
  id: string
  label: string
  agent: string
  status: WorkflowStatus
  input: string
  output: string
  purpose: string
}

export interface ThreatNarrative {
  executiveSummary?: string
  keyFindings: string[]
  threatAssessment?: string
  abuseScenarios: string[]
  riskExplanation?: string
  riskScore?: number
  severity?: Severity
  recommendedActions: string[]
  confidence?: number
}

type AnyRecord = Record<string, unknown>

interface NormalizedItem {
  label: string
  subtitle?: string
  raw: unknown
  severity?: Severity
  riskScore?: number
  confidence?: number
  evidence: string[]
  reasoning?: string
  riskImpact?: string
  recommendations: string[]
  artifacts: Array<{ label: string; value: string }>
}

interface CategoryDefinition {
  id: string
  label: string
  kind: Exclude<InvestigationNodeKind, 'apk' | 'group'>
  relation: string
  relationshipKind: RelationshipKind
  purpose: string
  values: unknown[]
}

const isRecord = (value: unknown): value is AnyRecord =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const record = (value: unknown): AnyRecord => (isRecord(value) ? value : {})

const array = (value: unknown): unknown[] => {
  if (Array.isArray(value)) return value
  if (value === undefined || value === null || value === '') return []
  return [value]
}

const primitiveString = (value: unknown): string | undefined => {
  if (typeof value === 'string' && value.trim()) return value.trim()
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return undefined
}

const firstString = (source: AnyRecord, keys: string[]): string | undefined => {
  for (const key of keys) {
    const value = primitiveString(source[key])
    if (value) return value
  }
  return undefined
}

const firstNumber = (source: AnyRecord, keys: string[]): number | undefined => {
  for (const key of keys) {
    const candidate = source[key]
    const value = typeof candidate === 'number' ? candidate : Number(candidate)
    if (Number.isFinite(value)) return value
  }
  return undefined
}

const normalizeSeverity = (value: unknown): Severity | undefined => {
  const normalized = primitiveString(value)?.toLowerCase()
  if (!normalized) return undefined
  if (normalized.includes('critical')) return 'critical'
  if (normalized.includes('high')) return 'high'
  if (normalized.includes('medium') || normalized.includes('moderate')) return 'medium'
  if (normalized.includes('low')) return 'low'
  if (normalized.includes('info')) return 'info'
  return undefined
}

const stringsFrom = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    return value.flatMap(item => stringsFrom(item)).filter(Boolean)
  }
  const direct = primitiveString(value)
  if (direct) return [direct]
  if (!isRecord(value)) return []

  return Object.values(value).flatMap(item => stringsFrom(item)).filter(Boolean)
}

const displayKey = (key: string): string =>
  key.replace(/_/g, ' ').replace(/\b\w/g, character => character.toUpperCase())

const compactValue = (value: unknown): string | undefined => {
  const direct = primitiveString(value)
  if (direct) return direct
  if (Array.isArray(value)) {
    const values = value.map(item => primitiveString(item)).filter((item): item is string => Boolean(item))
    if (values.length) return values.slice(0, 4).join(', ')
  }
  return undefined
}

const artifactsFrom = (source: AnyRecord): Array<{ label: string; value: string }> => {
  const ignored = new Set(['evidence', 'recommendations', 'findings', 'reasoning', 'description', 'summary'])
  return Object.entries(source)
    .filter(([key]) => !ignored.has(key))
    .map(([key, value]) => ({ label: displayKey(key), value: compactValue(value) }))
    .filter((item): item is { label: string; value: string } => Boolean(item.value))
    .slice(0, 10)
}

const truncate = (value: string, length = 56): string =>
  value.length > length ? `${value.slice(0, length - 3)}...` : value

const stableId = (value: string): string => {
  let hash = 0
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0
  }
  return hash.toString(36)
}

const normalizeItem = (value: unknown, fallbackLabel: string): NormalizedItem => {
  if (!isRecord(value)) {
    const label = primitiveString(value) || fallbackLabel
    return {
      label,
      raw: value,
      evidence: [label],
      recommendations: [],
      artifacts: [{ label: 'Value', value: label }]
    }
  }

  const label = firstString(value, [
    'name',
    'value',
    'permission',
    'function_name',
    'method_name',
    'title',
    'action',
    'objective',
    'technique_name',
    'technique',
    'url',
    'domain',
    'ip',
    'fingerprint',
    'subject',
    'id'
  ]) || fallbackLabel
  const subtitle = firstString(value, ['type', 'category', 'package', 'class_name', 'issuer', 'priority'])
  const reasoning = firstString(value, ['reasoning', 'reason', 'description', 'summary', 'rationale'])
  const riskImpact = firstString(value, ['risk_impact', 'impact', 'abuse', 'threat_impact'])
  const evidence = stringsFrom(value.evidence ?? value.artifacts ?? value.indicators)
  const recommendations = stringsFrom(value.recommendations ?? value.recommended_actions)

  return {
    label,
    subtitle,
    raw: value,
    severity: normalizeSeverity(value.severity ?? value.priority ?? value.threat_level),
    riskScore: firstNumber(value, ['risk_score', 'score', 'risk']),
    confidence: firstNumber(value, ['confidence', 'confidence_score']),
    evidence: evidence.length ? evidence : reasoning ? [reasoning] : [],
    reasoning,
    riskImpact,
    recommendations,
    artifacts: artifactsFrom(value)
  }
}

const uniqueValues = (values: unknown[]): unknown[] => {
  const seen = new Set<string>()
  return values.filter(value => {
    const item = normalizeItem(value, 'Artifact')
    const key = `${item.label.toLowerCase()}::${item.subtitle || ''}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

const hasOwn = (source: AnyRecord, key: string): boolean =>
  Object.prototype.hasOwnProperty.call(source, key)

const childRecord = (source: AnyRecord, key: string): AnyRecord => record(source[key])

const flattenedIocs = (iocs: AnyRecord, excluded: Set<string>): unknown[] =>
  Object.entries(iocs).flatMap(([type, values]) => {
    if (excluded.has(type.toLowerCase())) return []
    return array(values).map(value => isRecord(value) ? value : { type, value })
  })

const analysisParts = (analysis: AnyRecord) => {
  const apk = Object.keys(record(analysis.apk_analysis)).length ? record(analysis.apk_analysis) : analysis
  const threat = Object.keys(record(analysis.threat_assessment)).length
    ? record(analysis.threat_assessment)
    : record(analysis.risk_assessment)
  const intelligence = record(analysis.intelligence)
  const iocs = record(threat.iocs ?? intelligence.iocs ?? analysis.iocs)
  return { apk, threat, intelligence, iocs }
}

const categoryDefinitions = (analysis: AnyRecord): CategoryDefinition[] => {
  const { apk, threat, intelligence, iocs } = analysisParts(analysis)
  const files = childRecord(apk, 'files')
  const resources = childRecord(apk, 'resources')
  const excludedIocs = new Set(['url', 'urls', 'domain', 'domains', 'ip', 'ips', 'ip_addresses'])

  const manifestValue = apk.manifest
  const riskValue = Object.keys(threat).length ? [threat] : []
  const recommendations = array(analysis.recommendations ?? intelligence.recommendations)
  const findings = [
    ...array(threat.findings),
    ...array(threat.indicators),
    ...array(analysis.key_findings),
    ...array(analysis.attack_mapping)
  ]

  const definitions: CategoryDefinition[] = [
    { id: 'manifest', label: 'Manifest', kind: 'manifest', relation: 'parsed from', relationshipKind: 'analysis', purpose: 'Android package identity, SDK constraints, and declared application configuration.', values: manifestValue ? [manifestValue] : [] },
    { id: 'permissions', label: 'Permissions', kind: 'permission', relation: 'declares', relationshipKind: 'evidence', purpose: 'Capabilities requested by the APK through its Android manifest.', values: array(apk.permissions) },
    { id: 'activities', label: 'Activities', kind: 'activity', relation: 'declares', relationshipKind: 'evidence', purpose: 'User-facing Android entry points declared by the package.', values: array(apk.activities) },
    { id: 'services', label: 'Services', kind: 'service', relation: 'declares', relationshipKind: 'evidence', purpose: 'Background execution components declared by the package.', values: array(apk.services) },
    { id: 'receivers', label: 'Receivers', kind: 'receiver', relation: 'declares', relationshipKind: 'evidence', purpose: 'Broadcast receivers and event-driven entry points declared by the package.', values: array(apk.receivers) },
    { id: 'providers', label: 'Providers', kind: 'provider', relation: 'declares', relationshipKind: 'evidence', purpose: 'Content providers and shared data interfaces declared by the package.', values: array(apk.providers) },
    { id: 'strings', label: 'Strings', kind: 'string', relation: 'contains', relationshipKind: 'evidence', purpose: 'Strings recovered from package resources or static extraction.', values: array(apk.strings ?? apk.extracted_strings ?? resources.strings) },
    { id: 'certificates', label: 'Certificates', kind: 'certificate', relation: 'signed by', relationshipKind: 'evidence', purpose: 'Signing identities and certificate metadata extracted from the APK.', values: array(apk.certificates ?? apk.certificate) },
    { id: 'domains', label: 'Domains', kind: 'domain', relation: 'references', relationshipKind: 'correlation', purpose: 'Domain indicators extracted from package content or threat intelligence.', values: [...array(apk.domains), ...array(iocs.domains ?? iocs.domain)] },
    { id: 'urls', label: 'URLs', kind: 'url', relation: 'references', relationshipKind: 'correlation', purpose: 'Network locations recovered from static or intelligence analysis.', values: [...array(apk.urls), ...array(iocs.urls ?? iocs.url)] },
    { id: 'ips', label: 'IP Addresses', kind: 'ip', relation: 'references', relationshipKind: 'correlation', purpose: 'IP indicators recovered from static or intelligence analysis.', values: [...array(apk.ip_addresses ?? apk.ips), ...array(iocs.ip_addresses ?? iocs.ips ?? iocs.ip)] },
    { id: 'functions', label: 'Suspicious Functions', kind: 'function', relation: 'contains', relationshipKind: 'analysis', purpose: 'Functions ranked by the existing analysis pipeline for investigative review.', values: array(analysis.top_suspicious_functions ?? analysis.suspicious_functions) },
    { id: 'libraries', label: 'Native Libraries', kind: 'library', relation: 'contains', relationshipKind: 'evidence', purpose: 'Native libraries and DEX artifacts discovered in the package.', values: [...array(apk.native_libraries), ...array(files.dex_files)] },
    { id: 'findings', label: 'Threat Findings', kind: 'finding', relation: 'produced', relationshipKind: 'assessment', purpose: 'Findings emitted by threat scoring, attack mapping, and correlation stages.', values: findings },
    { id: 'iocs', label: 'Other IOCs', kind: 'ioc', relation: 'correlates', relationshipKind: 'correlation', purpose: 'Additional indicators of compromise returned by the analysis pipeline.', values: flattenedIocs(iocs, excludedIocs) },
    { id: 'risk', label: 'Risk Assessment', kind: 'risk', relation: 'assessed as', relationshipKind: 'assessment', purpose: 'Risk score, severity, and supporting explanation produced by the analysis pipeline.', values: riskValue },
    { id: 'recommendations', label: 'Recommendations', kind: 'recommendation', relation: 'recommends', relationshipKind: 'assessment', purpose: 'Analyst actions generated from the observed evidence and assessed risk.', values: recommendations }
  ]

  return definitions.map(definition => ({ ...definition, values: uniqueValues(definition.values) }))
}

const categoryColorPurpose = (definition: CategoryDefinition): string => definition.purpose

export const buildInvestigationGraph = (
  evidence: Evidence,
  analysisValue: unknown,
  expandedGroups: Set<string>,
  groupLimits: Record<string, number>
): InvestigationGraphModel => {
  const analysis = record(analysisValue)
  const { apk } = analysisParts(analysis)
  const categories = categoryDefinitions(analysis).filter(definition => definition.values.length > 0)
  const nodes: InvestigationNode[] = []
  const edges: InvestigationEdge[] = []
  const rootId = `apk:${evidence.id}`
  const groupSpacing = 152
  const centerY = Math.max(0, ((categories.length - 1) * groupSpacing) / 2)
  const appLabel = firstString(apk, ['app_name', 'package_name']) || evidence.original_filename

  nodes.push({
    id: rootId,
    label: appLabel,
    subtitle: firstString(apk, ['package_name', 'version_name']) || evidence.original_filename,
    kind: 'apk',
    x: 40,
    y: centerY,
    width: 210,
    height: 76,
    severity: normalizeSeverity(analysis.threat_level),
    riskScore: firstNumber(analysis, ['risk_score']),
    purpose: 'Primary APK evidence selected for this investigation.',
    evidence: [evidence.original_filename, evidence.sha256].filter(Boolean),
    reasoning: 'Root evidence record returned by the case evidence API.',
    recommendations: [],
    artifacts: [
      { label: 'Filename', value: evidence.original_filename },
      { label: 'SHA-256', value: evidence.sha256 },
      ...(firstString(apk, ['package_name']) ? [{ label: 'Package', value: firstString(apk, ['package_name']) as string }] : []),
      ...(firstString(apk, ['version_name']) ? [{ label: 'Version', value: firstString(apk, ['version_name']) as string }] : [])
    ],
    raw: evidence
  })

  categories.forEach((definition, categoryIndex) => {
    const groupId = `group:${definition.id}`
    const groupY = categoryIndex * groupSpacing
    const expanded = expandedGroups.has(groupId)
    const requestedLimit = groupLimits[groupId] || 18
    const visibleValues = expanded ? definition.values.slice(0, requestedLimit) : []

    nodes.push({
      id: groupId,
      label: definition.label,
      subtitle: `${definition.values.length} artifact${definition.values.length === 1 ? '' : 's'}`,
      kind: 'group',
      x: 390,
      y: groupY,
      width: 188,
      height: 64,
      count: definition.values.length,
      loadedCount: visibleValues.length,
      expandable: true,
      purpose: categoryColorPurpose(definition),
      evidence: [],
      reasoning: `This collection is populated from the ${definition.label.toLowerCase()} fields returned by the existing analysis pipeline.`,
      recommendations: [],
      artifacts: [{ label: 'Artifact Count', value: String(definition.values.length) }],
      raw: definition.values
    })

    edges.push({
      id: `${rootId}->${groupId}`,
      source: rootId,
      target: groupId,
      label: definition.relation,
      kind: definition.relationshipKind
    })

    visibleValues.forEach((value, itemIndex) => {
      const item = normalizeItem(value, `${definition.label} ${itemIndex + 1}`)
      const childId = `${definition.id}:${stableId(`${item.label}:${itemIndex}`)}`
      const childY = groupY + (itemIndex - (visibleValues.length - 1) / 2) * 72

      nodes.push({
        id: childId,
        label: truncate(item.label),
        subtitle: item.subtitle,
        kind: definition.kind,
        x: 742,
        y: childY,
        width: 212,
        height: 58,
        groupId,
        severity: item.severity,
        riskScore: item.riskScore,
        confidence: item.confidence,
        purpose: definition.purpose,
        evidence: item.evidence,
        reasoning: item.reasoning,
        riskImpact: item.riskImpact,
        recommendations: item.recommendations,
        artifacts: item.artifacts,
        raw: item.raw
      })

      edges.push({
        id: `${groupId}->${childId}`,
        source: groupId,
        target: childId,
        label: definition.relation,
        kind: definition.relationshipKind
      })
    })
  })

  const visibleDomainNodes = nodes.filter(node => node.kind === 'domain')
  nodes.filter(node => node.kind === 'url').forEach(urlNode => {
    try {
      const hostname = new URL(urlNode.label).hostname.toLowerCase()
      const domainNode = visibleDomainNodes.find(node => node.label.toLowerCase() === hostname)
      if (domainNode) {
        edges.push({
          id: `${urlNode.id}->${domainNode.id}`,
          source: urlNode.id,
          target: domainNode.id,
          label: 'resolves host',
          kind: 'correlation'
        })
      }
    } catch {
      // The analysis value is retained as evidence even when it is not a parseable URL.
    }
  })

  const minY = Math.min(...nodes.map(node => node.y - node.height / 2), -120)
  const maxY = Math.max(...nodes.map(node => node.y + node.height / 2), 120)

  return {
    nodes,
    edges,
    totalEntityCount: categories.reduce((total, definition) => total + definition.values.length, 1),
    bounds: { minX: -120, minY, maxX: 1080, maxY }
  }
}

const countFrom = (...values: unknown[]): number => values.reduce<number>((total, value) => total + array(value).length, 0)

export const buildWorkflowStages = (evidence: Evidence | null, analysisValue: unknown): WorkflowStage[] => {
  const analysis = record(analysisValue)
  const { apk, threat, intelligence, iocs } = analysisParts(analysis)
  const components = countFrom(apk.activities, apk.services, apk.receivers, apk.providers)
  const status = evidence?.analysis_status?.toLowerCase() || ''
  const analysisComplete = status === 'complete' || status === 'analyzed'
  const analysisRunning = ['analyzing', 'processing', 'running', 'in_progress'].includes(status)
  const analysisFailed = status === 'failed' || status === 'error'
  const narrative = extractThreatNarrative(analysis)

  const definitions = [
    {
      id: 'manifest',
      label: 'Manifest Analysis',
      agent: 'Threat Analyst Agent',
      input: evidence ? 'APK package' : 'Awaiting APK',
      output: firstString(apk, ['package_name']) || (hasOwn(apk, 'manifest') ? 'Manifest parsed' : 'No output'),
      purpose: 'Establish package identity, SDK constraints, and declared application structure.',
      hasOutput: hasOwn(apk, 'manifest') || Boolean(firstString(apk, ['package_name']))
    },
    {
      id: 'permissions',
      label: 'Permission Analysis',
      agent: 'Permission Analyst Agent',
      input: 'Parsed manifest',
      output: `${array(apk.permissions).length} permissions`,
      purpose: 'Inspect declared capabilities and permission evidence.',
      hasOutput: hasOwn(apk, 'permissions')
    },
    {
      id: 'components',
      label: 'Component Analysis',
      agent: 'Behavior Analyst Agent',
      input: 'Manifest components',
      output: `${components} components`,
      purpose: 'Map activities, services, receivers, and providers.',
      hasOutput: ['activities', 'services', 'receivers', 'providers'].some(key => hasOwn(apk, key))
    },
    {
      id: 'certificates',
      label: 'Certificate Analysis',
      agent: 'Certificate Analyst Agent',
      input: 'APK signatures',
      output: `${countFrom(apk.certificates ?? apk.certificate)} certificates`,
      purpose: 'Inspect signing identity and certificate metadata.',
      hasOutput: hasOwn(apk, 'certificates') || hasOwn(apk, 'certificate')
    },
    {
      id: 'network',
      label: 'Network Analysis',
      agent: 'Network Analyst Agent',
      input: 'Extracted artifacts',
      output: `${countFrom(apk.urls, apk.domains, apk.ip_addresses, apk.ips)} indicators`,
      purpose: 'Extract network locations and communication indicators.',
      hasOutput: ['urls', 'domains', 'ip_addresses', 'ips'].some(key => hasOwn(apk, key))
    },
    {
      id: 'correlation',
      label: 'IOC Correlation',
      agent: 'Threat Correlation Agent',
      input: 'Network and static IOCs',
      output: `${stringsFrom(iocs).length} correlated values`,
      purpose: 'Correlate extracted indicators with the pipeline threat context.',
      hasOutput: Object.keys(iocs).length > 0 || hasOwn(analysis, 'attack_mapping')
    },
    {
      id: 'risk',
      label: 'Risk & Fraud Scoring',
      agent: 'Fraud Investigation Agent',
      input: 'Correlated findings',
      output: narrative.riskScore === undefined ? 'No score' : `${narrative.riskScore}/100`,
      purpose: 'Score observed threat and abuse evidence.',
      hasOutput: Object.keys(threat).length > 0 || hasOwn(analysis, 'fraud_intent')
    },
    {
      id: 'narrative',
      label: 'Threat Narrative',
      agent: 'Executive Reporting Agent',
      input: 'Assessment evidence',
      output: narrative.executiveSummary ? 'Narrative generated' : 'No narrative',
      purpose: 'Assemble the executive assessment, findings, and recommended actions.',
      hasOutput: Boolean(narrative.executiveSummary) || Object.keys(intelligence).length > 0
    }
  ]

  const firstIncomplete = definitions.findIndex(definition => !definition.hasOutput)

  return definitions.map((definition, index) => {
    let stageStatus: WorkflowStatus = 'pending'
    if (evidence && (analysisComplete || definition.hasOutput)) stageStatus = 'completed'
    if (analysisRunning && index === (firstIncomplete === -1 ? definitions.length - 1 : firstIncomplete)) stageStatus = 'running'
    if (analysisFailed && index === (firstIncomplete === -1 ? definitions.length - 1 : firstIncomplete)) stageStatus = 'failed'
    return { ...definition, status: stageStatus }
  })
}

const firstNarrativeString = (...values: unknown[]): string | undefined => {
  for (const value of values) {
    const direct = primitiveString(value)
    if (direct) return direct
    if (isRecord(value)) {
      const nested = firstString(value, ['summary', 'content', 'text', 'assessment', 'explanation'])
      if (nested) return nested
    }
  }
  return undefined
}

const normalizedList = (...values: unknown[]): string[] => {
  const normalized = values.flatMap(value => array(value)).flatMap(item => {
    if (isRecord(item)) {
      return [firstString(item, ['finding', 'title', 'summary', 'description', 'objective', 'action', 'name', 'value'])]
    }
    return [primitiveString(item)]
  }).filter((item): item is string => Boolean(item))
  return [...new Set(normalized)]
}

export const extractThreatNarrative = (analysisValue: unknown): ThreatNarrative => {
  const analysis = record(analysisValue)
  const { threat, intelligence } = analysisParts(analysis)
  const aiAnalysis = record(analysis.ai_analysis)
  const fraud = record(analysis.fraud_intent)
  const attackFlow = record(analysis.attack_flow)
  const scoreBreakdown = record(threat.score_breakdown)
  const riskScore = firstNumber(threat, ['risk_score', 'overall_risk', 'score'])
    ?? firstNumber(analysis, ['risk_score', 'overall_risk'])
  const confidence = firstNumber(analysis, ['confidence', 'confidence_score'])
    ?? firstNumber(intelligence, ['confidence', 'confidence_score'])
    ?? firstNumber(attackFlow, ['confidence', 'confidence_score'])
  const riskExplanation = firstNarrativeString(
    threat.risk_score_explanation,
    threat.summary,
    intelligence.risk_explanation,
    Object.keys(scoreBreakdown).length
      ? Object.entries(scoreBreakdown).map(([key, value]) => `${displayKey(key)}: ${String(value)}`).join(' | ')
      : undefined
  )

  return {
    executiveSummary: firstNarrativeString(
      analysis.executive_summary,
      intelligence.executive_summary,
      aiAnalysis.executive_summary,
      threat.summary
    ),
    keyFindings: normalizedList(analysis.key_findings, intelligence.key_findings, threat.findings, threat.indicators),
    threatAssessment: firstNarrativeString(analysis.threat_assessment, intelligence.threat_assessment, threat.summary),
    abuseScenarios: normalizedList(
      analysis.potential_abuse_scenarios,
      intelligence.potential_abuse_scenarios,
      fraud.objectives,
      attackFlow.steps
    ),
    riskExplanation,
    riskScore,
    severity: normalizeSeverity(threat.severity ?? analysis.threat_level),
    recommendedActions: normalizedList(
      analysis.recommendations,
      intelligence.recommendations,
      aiAnalysis.recommended_actions,
      aiAnalysis.recommendations
    ),
    confidence: confidence === undefined ? undefined : confidence <= 1 ? Math.round(confidence * 100) : Math.round(confidence)
  }
}
