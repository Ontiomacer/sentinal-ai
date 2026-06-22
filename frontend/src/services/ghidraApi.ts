/**
 * Ghidra Backend API Service
 * 
 * ALL Ghidra MCP communication goes through FastAPI backend.
 * Frontend NEVER communicates directly with MCP server.
 */

import axios from 'axios'

const API_BASE = 'http://localhost:8000/api/v1'

export interface GhidraFunction {
  name: string
  address: string
  size: number
  signature?: string
  is_external: boolean
  is_thunk?: boolean
  calling_convention?: string
}

export interface GhidraString {
  address: string
  value: string
  length: number
  encoding?: string
  references: string[]
}

export interface GhidraClass {
  name: string
  package: string
  methods: string[]
  fields: string[]
  super_class?: string
  interfaces?: string[]
}

export interface DecompiledCode {
  function_name: string
  address: string
  c_code: string
  signature: string
  variables: any[]
  calls_to: string[]
  called_by: string[]
}

export interface Disassembly {
  address: string
  function_name: string
  instructions: DisassemblyInstruction[]
}

export interface DisassemblyInstruction {
  address: string
  mnemonic: string
  opcode: string
  bytes: string
  comment?: string
}

export interface CrossReference {
  from_address: string
  from_name: string
  to_address: string
  to_name: string
  type: 'call' | 'jump' | 'reference' | 'data'
}

export interface SymbolMetadata {
  name: string
  address: string
  size?: number
  type: string
  namespace?: string
  class_name?: string
  signature?: string
  references_count?: number
  called_by_count?: number
  calls_count?: number
}

export interface GhidraHealth {
  connected: boolean
  latency_ms?: number
  endpoints: number
  last_check?: string
  error?: string
}

export interface GhidraDiagnostics {
  connected: boolean
  status: 'CONNECTED' | 'DEGRADED' | 'OFFLINE' | 'CONNECTING' | 'IMPORTING' | 'ANALYZING' | 'INDEXING' | 'READY' | 'FAILED'
  version?: string
  active_project?: string
  loaded_program?: string
  uptime_seconds: number
  endpoints_available: number
  analyzers_loaded: string[]
  decompiler_available: boolean
  debugger_available: boolean
  last_error?: string
  latency_ms: number
}

export interface GhidraMemorySection {
  name: string
  start: string
  end: string
  size: number
  permissions: string
  type: string
}

export interface GhidraImportExport {
  name: string
  address?: string
  library?: string
  type: 'import' | 'export'
  stable_id?: string
  namespace?: string
  class_name?: string
}

export interface GhidraSymbolNode {
  id: string
  name: string
  type: 'folder' | 'namespace' | 'class' | 'method' | 'function' | 'import' | 'export' | 'string'
  address?: string
  depth: number
  symbol_type?: string
  data: Record<string, any>
  children: GhidraSymbolNode[]
}

export interface GhidraSymbolTree {
  roots: GhidraSymbolNode[]
  counts: Record<string, number>
  first_function_id?: string
  first_function_address?: string
  max_depth: number
  generated_at: string
}

export interface GhidraCallGraph {
  nodes: Array<{ id: string; label: string; type?: string }>
  edges: Array<{ source: string; target: string; type?: string }>
  entry_points: string[]
}

export interface GhidraDebugState {
  execution_status: string
  active_thread?: string
  program_counter?: string
  loaded_module?: string
  threads: Array<{ id: string; name: string; state: string; pc: string }>
  registers: Array<{ name: string; value: string }>
  stack_frames: Array<{ frame: number; address: string; function: string; source: string }>
  breakpoints: Array<{ address: string; type: string; enabled: boolean; location: string }>
  memory_regions: Array<{ name: string; start: string; end: string; permissions: string; size: number }>
  logs: string[]
}

// Health check
export const checkGhidraHealth = async (): Promise<GhidraHealth> => {
  const response = await axios.get(`${API_BASE}/ghidra/health`)
  return response.data
}

// Get diagnostics
export const getGhidraDiagnostics = async (): Promise<GhidraDiagnostics> => {
  const response = await axios.get(`${API_BASE}/ghidra/diagnostics`)
  return response.data
}

// Get memory map
export const getMemoryMap = async (evidenceId: string): Promise<GhidraMemorySection[]> => {
  const response = await axios.get(`${API_BASE}/ghidra/memory/${evidenceId}`)
  return response.data
}

// Get imports/exports
export const getImportsExports = async (evidenceId: string): Promise<GhidraImportExport[]> => {
  const response = await axios.get(`${API_BASE}/ghidra/symbols/imports_exports/${evidenceId}`)
  return response.data
}

// Get recursive live symbol tree
export const getSymbolTree = async (evidenceId: string): Promise<GhidraSymbolTree> => {
  const response = await axios.get(`${API_BASE}/ghidra/symbols/tree/${evidenceId}`)
  return response.data
}

// Get functions
export const getFunctions = async (evidenceId: string, filterExternal: boolean = true): Promise<GhidraFunction[]> => {
  const response = await axios.get(`${API_BASE}/ghidra/functions/${evidenceId}`, {
    params: { filter_external: filterExternal }
  })
  return response.data
}

// Decompile function
export const decompileFunction = async (evidenceId: string, functionAddress: string): Promise<DecompiledCode> => {
  const response = await axios.get(`${API_BASE}/ghidra/decompile/${functionAddress}`, {
    params: { evidence_id: evidenceId }
  })
  return response.data
}

// Get disassembly (fallback: return empty if not available on backend)
export const getDisassembly = async (evidenceId: string, functionAddress: string): Promise<Disassembly> => {
  try {
    const response = await axios.get(`${API_BASE}/ghidra/disassemble/${functionAddress}`, {
      params: { evidence_id: evidenceId }
    })
    return response.data
  } catch (err) {
    console.warn(`Disassembly endpoint not available for ${functionAddress}`)
    return {
      address: functionAddress,
      function_name: 'unknown',
      instructions: []
    }
  }
}

// Get cross-references (fallback: return empty if not available)
export const getCrossReferences = async (evidenceId: string, functionAddress: string): Promise<CrossReference[]> => {
  try {
    const response = await axios.get(`${API_BASE}/ghidra/xrefs/${functionAddress}`, {
      params: { evidence_id: evidenceId }
    })
    return response.data
  } catch (err) {
    console.warn(`Cross-references endpoint not available for ${functionAddress}`)
    return []
  }
}

// Get classes
export const getClasses = async (evidenceId: string): Promise<GhidraClass[]> => {
  const response = await axios.get(`${API_BASE}/ghidra/classes/${evidenceId}`)
  return response.data
}

// Get strings
export const getStrings = async (evidenceId: string, minLength: number = 4): Promise<GhidraString[]> => {
  const response = await axios.get(`${API_BASE}/ghidra/strings/${evidenceId}`, {
    params: { min_length: minLength }
  })
  return response.data
}

export const getCallGraph = async (evidenceId: string, entryPoint?: string): Promise<GhidraCallGraph> => {
  const response = await axios.get(`${API_BASE}/ghidra/callgraph/${evidenceId}`, {
    params: { entry_point: entryPoint }
  })
  return response.data
}

export const getDebugState = async (evidenceId: string): Promise<GhidraDebugState> => {
  const response = await axios.get(`${API_BASE}/ghidra/debug/state/${evidenceId}`)
  return response.data
}

// Get APK structure
export const getApkStructure = async (evidenceId: string): Promise<any> => {
  const response = await axios.get(`${API_BASE}/ghidra/structure/${evidenceId}`)
  return response.data
}

// Trigger deep analysis
export const analyzeEvidence = async (evidenceId: string, deepAnalysis: boolean = true) => {
  const response = await axios.post(`${API_BASE}/ghidra/analyze/${evidenceId}`, null, {
    params: { deep_analysis: deepAnalysis }
  })
  return response.data
}

// Flatten symbol tree to searchable array
export const flattenSymbolTree = (roots: GhidraSymbolNode[]): GhidraSymbolNode[] => {
  const flattened: GhidraSymbolNode[] = []
  const stack = [...roots]
  while (stack.length > 0) {
    const node = stack.pop()
    if (!node) continue
    flattened.push(node)
    if (node.children?.length > 0) {
      stack.push(...node.children)
    }
  }
  return flattened
}

// Filter symbols by search query
export const searchSymbols = (symbols: GhidraSymbolNode[], query: string, typeFilter?: string[]): GhidraSymbolNode[] => {
  if (!query && !typeFilter) return symbols
  const lowerQuery = query.toLowerCase()
  return symbols.filter(sym => {
    const matchesQuery = !query || sym.name.toLowerCase().includes(lowerQuery)
    const matchesType = !typeFilter || typeFilter.includes(sym.type)
    return matchesQuery && matchesType
  })
}
