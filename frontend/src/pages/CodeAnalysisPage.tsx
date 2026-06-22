import React, { useState, useEffect, useRef } from 'react';
import { useParams } from 'react-router-dom';
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';
import Editor from '@monaco-editor/react';
import { 
  decompileFunction, 
  getApkStructure,
  getGhidraDiagnostics,
  getMemoryMap,
  getSymbolTree,
  getDisassembly,
  getCrossReferences,
  getCallGraph,
  getDebugState,
  DecompiledCode,
  Disassembly,
  CrossReference,
  GhidraDiagnostics,
  GhidraMemorySection,
  GhidraSymbolNode,
  GhidraSymbolTree,
  GhidraCallGraph,
  GhidraDebugState
} from '../services/ghidraApi';
import { getScan } from '../services/api';
import { listEvidence, getEvidence } from '../services/caseApi';
import { aiApi, AIExplainResponse } from '../services/aiApi';
import { cn } from '../utils/cn';
import VirtualizedExplorer from '../components/VirtualizedExplorer';
import DisassemblyView from '../components/DisassemblyView';
import CrossReferencesPanel from '../components/CrossReferencesPanel';
import SymbolMetadataPanel from '../components/SymbolMetadataPanel';
import MemoryVisualization from '../components/MemoryVisualization';
import StackVisualization from '../components/StackVisualization';
import RegisterVisualization from '../components/RegisterVisualization';
import CallGraphVisualization from '../components/CallGraphVisualization';

// ============================================================================
// Types & Interfaces
// ============================================================================

interface FileNode {
  id: string;
  name: string;
  type: string;
  children?: FileNode[];
  data?: any;
  isOpen?: boolean;
}

interface AnalysisEvent {
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'success';
  message: string;
  source: string;
}

interface WorkstationMetadata {
  original_filename?: string;
  filename?: string;
  status?: string;
  analysis_result?: {
    urls?: string[];
    [key: string]: any;
  };
  [key: string]: any;
}

type WorkspaceMode = 'CODE_BROWSER' | 'DEBUGGER';

/**
 * Diagnostic Banner for MCP Connection Status
 */
const DiagnosticBanner = ({ diagnostics, metadata }: { diagnostics: GhidraDiagnostics | null, metadata: any }) => {
  if (!diagnostics) return null;

  const currentStatus = metadata?.status || diagnostics.status;

  const getStatusColor = () => {
    switch (currentStatus) {
      case 'READY':
      case 'CONNECTED': return 'text-success border-success/30 bg-success/5';
      case 'CONNECTING':
      case 'IMPORTING':
      case 'ANALYZING':
      case 'INDEXING': return 'text-tertiary border-tertiary/30 bg-tertiary/5';
      case 'DEGRADED': return 'text-tertiary border-tertiary/30 bg-tertiary/5';
      case 'FAILED':
      case 'OFFLINE': return 'text-error border-error/30 bg-error/5';
      default: return 'text-error border-error/30 bg-error/5';
    }
  };

  return (
    <div className={cn("h-6 border-b flex items-center px-3 gap-4 shrink-0", getStatusColor())}>
      <div className="flex items-center gap-1.5">
        <span className={cn("w-1.5 h-1.5 rounded-full bg-current", ['READY', 'CONNECTED', 'OFFLINE', 'FAILED'].includes(currentStatus) ? "" : "animate-pulse")}></span>
        <span className="text-[9px] font-bold uppercase tracking-widest">{currentStatus}</span>
      </div>
      <div className="h-3 w-px bg-current opacity-20"></div>
      <div className="flex items-center gap-3 text-[9px] font-mono">
        <span className="opacity-70">VERSION: {diagnostics.version || '9.2.4'}</span>
        <span className="opacity-70">LATENCY: {diagnostics.latency_ms.toFixed(1)}ms</span>
        <span className="opacity-70">ENDPOINTS: {diagnostics.endpoints_available}</span>
        {diagnostics.loaded_program && (
          <span className="text-secondary font-bold">PROGRAM: {diagnostics.loaded_program}</span>
        )}
      </div>
      <div className="ml-auto flex items-center gap-2">
        <span className="text-[9px] font-bold opacity-50 uppercase">Analyzers: {diagnostics.analyzers_loaded.length}</span>
      </div>
    </div>
  );
};

/**
 * Enhanced Tree Item with professional RE tool aesthetic
 */
const TreeItem = ({ 
  node, 
  level = 0, 
  onSelect, 
  selectedId 
}: { 
  node: FileNode; 
  level?: number; 
  onSelect: (node: FileNode) => void;
  selectedId?: string;
}) => {
  const [isOpen, setIsOpen] = useState(node.isOpen || false);
  const hasChildren = node.children && node.children.length > 0;

  const getIcon = (type: FileNode['type']) => {
    switch (type) {
      case 'package': return 'package_2';
      case 'namespace': return 'account_tree';
      case 'class': return 'description';
      case 'method': return 'function';
      case 'function': return 'function';
      case 'resource': return 'image';
      case 'manifest': return 'article';
      case 'cert': return 'verified_user';
      case 'lib': return 'settings_input_component';
      case 'import': return 'login';
      case 'export': return 'logout';
      case 'section': return 'view_quilt';
      case 'string': return 'format_quote';
      case 'folder': return 'folder';
      default: return 'insert_drive_file';
    }
  };

  const getIconColor = (type: FileNode['type']) => {
    switch (type) {
      case 'package': return 'text-primary/70';
      case 'namespace': return 'text-primary/60';
      case 'class': return 'text-secondary/70';
      case 'method': return 'text-tertiary/70';
      case 'function': return 'text-tertiary/70';
      case 'lib': return 'text-error/70';
      case 'import': return 'text-primary/70';
      case 'export': return 'text-success/70';
      default: return 'text-on-surface-variant/50';
    }
  };

  return (
    <div className="select-none">
      <div 
        className={cn(
          "flex items-center py-0.5 px-2 cursor-pointer transition-colors group relative",
          selectedId === node.id ? "bg-secondary/10 text-secondary" : "hover:bg-white/5 text-on-surface-variant hover:text-on-surface"
        )}
        style={{ paddingLeft: `${level * 12 + 8}px` }}
        onClick={() => {
          if (hasChildren) setIsOpen(!isOpen);
          onSelect(node);
        }}
      >
        {selectedId === node.id && (
          <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-secondary shadow-[0_0_8px_rgba(var(--secondary-rgb),0.5)]"></div>
        )}
        
        <span className="material-symbols-outlined text-[14px] mr-1 opacity-40 group-hover:opacity-100 transition-opacity">
          {hasChildren ? (isOpen ? 'expand_more' : 'chevron_right') : ''}
        </span>
        <span className={cn("material-symbols-outlined text-[16px] mr-2", getIconColor(node.type))}>
          {getIcon(node.type)}
        </span>
        <span className="text-[12px] font-mono truncate leading-relaxed">{node.name}</span>
        
        {node.data?.suspicious && (
          <span className="ml-auto w-1.5 h-1.5 rounded-full bg-error shadow-[0_0_4px_rgba(var(--error-rgb),0.5)]"></span>
        )}
      </div>
      
      {isOpen && hasChildren && (
        <div className="relative">
          <div className="absolute left-[15px] top-0 bottom-0 w-px bg-white/5"></div>
          {node.children!.map(child => (
            <TreeItem 
              key={child.id} 
              node={child} 
              level={level + 1} 
              onSelect={onSelect}
              selectedId={selectedId}
            />
          ))}
        </div>
      )}
    </div>
  );
};

/**
 * Intelligence Module Card
 */
const IntelligenceCard = ({ 
  title, 
  icon, 
  children, 
  badge, 
  badgeType = 'info',
  collapsible = true 
}: { 
  title: string; 
  icon: string; 
  children: React.ReactNode; 
  badge?: string | number;
  badgeType?: 'info' | 'error' | 'success' | 'warn';
  collapsible?: boolean;
}) => {
  const [isCollapsed, setIsCollapsed] = useState(false);

  return (
    <div className="mono-panel bg-black/70 border border-white/10 rounded-lg overflow-hidden transition-all hover:border-white/25 group">
      <div 
        className={cn(
          "px-3 py-2 flex items-center justify-between cursor-pointer bg-white/[0.02]",
          isCollapsed && "border-b-0"
        )}
        onClick={() => collapsible && setIsCollapsed(!isCollapsed)}
      >
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-[18px] text-secondary/70">{icon}</span>
          <span className="text-[10px] font-bold uppercase tracking-[0.1em] text-on-surface-variant group-hover:text-on-surface transition-colors">
            {title}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {badge !== undefined && (
            <span className={cn(
              "px-1.5 py-0.5 rounded text-[9px] font-mono font-bold",
              badgeType === 'error' ? "bg-error/10 text-error border border-error/20" :
              badgeType === 'success' ? "bg-success/10 text-success border border-success/20" :
              badgeType === 'warn' ? "bg-tertiary/10 text-tertiary border border-tertiary/20" :
              "bg-primary/10 text-primary border border-primary/20"
            )}>
              {badge}
            </span>
          )}
          {collapsible && (
            <span className="material-symbols-outlined text-[16px] opacity-30 group-hover:opacity-100 transition-opacity">
              {isCollapsed ? 'add' : 'remove'}
            </span>
          )}
        </div>
      </div>
      {!isCollapsed && (
        <div className="p-3">
          {children}
        </div>
      )}
    </div>
  );
};

// ============================================================================
// Main Workspace Component
// ============================================================================

const CodeAnalysisPage = () => {
  const { caseId, scanId: routeScanId } = useParams<{ caseId?: string; scanId?: string }>();
  
  // Workspace State
  const [mode, setMode] = useState<WorkspaceMode>('CODE_BROWSER');
  const [loading, setLoading] = useState(true);
  const [activeEvidenceId, setActiveEvidenceId] = useState<string | null>(null);
  const [diagnostics, setDiagnostics] = useState<GhidraDiagnostics | null>(null);
  const [scan, setScan] = useState<WorkstationMetadata | null>(null);
  
  // Data State
  const [treeData, setTreeData] = useState<FileNode[]>([]);
  const [selectedNode, setSelectedNode] = useState<FileNode | null>(null);
  const [decompiledCode, setDecompiledCode] = useState<DecompiledCode | null>(null);
  const [disassembly, setDisassembly] = useState<Disassembly | null>(null);
  const [crossReferences, setCrossReferences] = useState<{ calledBy: CrossReference[]; calls: CrossReference[] }>({ calledBy: [], calls: [] });
  const [debugState, setDebugState] = useState<GhidraDebugState | null>(null);
  const [callGraph, setCallGraph] = useState<GhidraCallGraph | null>(null);
  const [isDecompiling, setIsDecompiling] = useState(false);
  const [isLoadingDisassembly, setIsLoadingDisassembly] = useState(false);
  const [isLoadingXrefs, setIsLoadingXrefs] = useState(false);
  const [isLoadingDebugState, setIsLoadingDebugState] = useState(false);
  const [isLoadingCallGraph, setIsLoadingCallGraph] = useState(false);
  const [codeInsight, setCodeInsight] = useState<AIExplainResponse | null>(null);
  const [isExplainingCode, setIsExplainingCode] = useState(false);
  const [symbolCounts, setSymbolCounts] = useState<Record<string, number>>({});
  const [autoSelectionAttempted, setAutoSelectionAttempted] = useState(false);
  const [events, setEvents] = useState<AnalysisEvent[]>([]);
  
  // UI State
  const [searchQuery, setSearchQuery] = useState('');
  const [activeBottomTab, setActiveBottomTab] = useState('CONSOLE');
  const [activeCenterTab, setActiveCenterTab] = useState('DECOMPILER');
  
  const editorRef = useRef<any>(null);

  // Initial Load & Diagnostics Polling
  useEffect(() => {
    const init = async () => {
      if (caseId) {
        try {
          const evidence = await listEvidence(caseId);
          const apkEvidence = evidence.filter(e => String(e.evidence_type).toLowerCase() === 'apk');
          if (routeScanId) setActiveEvidenceId(routeScanId);
          else if (apkEvidence.length > 0) setActiveEvidenceId(apkEvidence[0].id);
        } catch (err) { addEvent('error', `Forensic Vault Access Denied for case ${caseId}`); }
      } else if (routeScanId) {
        setActiveEvidenceId(routeScanId);
      }
    };
    init();

    // Poll Diagnostics
    const pollDiag = async () => {
      try {
        const d = await getGhidraDiagnostics();
        setDiagnostics(d);
      } catch (e) {
        setDiagnostics(prev => prev ? { ...prev, status: 'OFFLINE', connected: false } : null);
      }
    };
    pollDiag();
    const interval = setInterval(pollDiag, 15000);
    return () => clearInterval(interval);
  }, [caseId, routeScanId]);

  useEffect(() => {
    if (activeEvidenceId) {
      loadForensicData(activeEvidenceId);
    }
  }, [activeEvidenceId]);

  useEffect(() => {
    if (mode === 'DEBUGGER' && activeEvidenceId) {
      loadDebuggerData(activeEvidenceId);
    }
  }, [mode, activeEvidenceId]);

  useEffect(() => {
    setActiveCenterTab(mode === 'DEBUGGER' ? 'OVERVIEW' : 'DECOMPILER');
  }, [mode]);

  const loadDebuggerData = async (evidenceId: string) => {
    try {
      setIsLoadingDebugState(true);
      setIsLoadingCallGraph(true);
      addEvent('info', `Loading dynamic debugger state for ${evidenceId}`);

      const [state, graph] = await Promise.all([
        getDebugState(evidenceId).catch((error) => {
          console.warn('Debug state unavailable', error);
          return null;
        }),
        getCallGraph(evidenceId).catch((error) => {
          console.warn('Call graph unavailable', error);
          return null;
        })
      ]);

      setDebugState(state);
      setCallGraph(graph);
      if (state) addEvent('success', `Debugger state loaded: ${state.execution_status}`);
      if (graph) addEvent('success', `Call graph loaded: ${graph.nodes.length} nodes`);
    } catch (error) {
      console.error('Failed to load debugger state', error);
      addEvent('warn', 'Debugger environment partially degraded');
    } finally {
      setIsLoadingDebugState(false);
      setIsLoadingCallGraph(false);
    }
  };

  const addEvent = (level: AnalysisEvent['level'], message: string, source: string = 'GhidraEngine') => {
    setEvents(prev => [{
      timestamp: new Date().toLocaleTimeString(),
      level,
      message,
      source
    }, ...prev].slice(0, 100));
  };

  const loadForensicData = async (evidenceId: string) => {
    try {
      setLoading(true);
      addEvent('info', `Synchronizing workstation with evidence: ${evidenceId}`);
      
      const [symbolTree, structure, memory] = await Promise.all([
        getSymbolTree(evidenceId),
        getApkStructure(evidenceId).catch(() => ({ 
          apk_analysis: { package_name: 'Unknown', permissions: [] },
          ghidra_analysis: { status: 'unavailable' }
        })),
        getMemoryMap(evidenceId).catch(() => [])
      ]);

      addEvent(
        'info',
        `Live symbol traversal complete: ${symbolTree.counts.nodes || 0} nodes, depth ${symbolTree.max_depth}`
      );
      
      // Fetch metadata (try Evidence API first, then Scan API)
      let metadata: any = null;
      try {
        if (caseId) {
          const evidenceData = await getEvidence(caseId, evidenceId);
          metadata = {
            original_filename: evidenceData.original_filename,
            analysis_result: evidenceData.analysis_result,
            status: evidenceData.analysis_status
          };
        } else {
          const scanData = await getScan(evidenceId);
          metadata = scanData;
        }
      } catch (e) {
        // Fallback for hybrid scenarios
        try {
          metadata = await getScan(evidenceId);
        } catch (e2) {
          addEvent('warn', 'Extended metadata retrieval degraded');
        }
      }
      setScan(metadata);
      setSymbolCounts(symbolTree.counts);

      const tree = buildExplorerTree(symbolTree, memory, structure);
      setTreeData(tree);
      
      addEvent('info', `Symbol tree loaded: ${tree.length} top-level nodes`);
      addEvent('info', `Symbol counts: functions=${symbolTree.counts.functions || 0}, imports=${symbolTree.counts.imports || 0}, exports=${symbolTree.counts.exports || 0}`);

      const firstNode = (
        symbolTree.first_function_id ? findNodeById(tree, symbolTree.first_function_id) : null
      ) || findFirstDecompilableNode(tree);

      if (firstNode) {
        addEvent('info', `Attempting auto-selection: ${firstNode.name} (${firstNode.id})`);
        setAutoSelectionAttempted(true);
        await handleNodeSelect(firstNode);
        addEvent('info', `Auto-selected first decompilable symbol: ${firstNode.name}`);
      } else {
        setAutoSelectionAttempted(true);
        addEvent('warn', 'No decompilable symbol was found in the current symbol tree');
      }
      
      if (metadata?.status && ['indexing', 'static_analysis', 'ghidra_analysis', 'ai_correlation'].includes(metadata.status)) {
        const statusMap: Record<string, string> = {
          'indexing': 'UNZIPPING APK & EXTRACTING DEX...',
          'static_analysis': 'IMPORTING DEX INTO GHIDRA...',
          'ghidra_analysis': 'RUNNING GHIDRA AUTO-ANALYZERS...',
          'ai_correlation': 'INDEXING FUNCTIONS & SYMBOLS...'
        };
        addEvent('info', statusMap[metadata.status] || 'ANALYZING ARTIFACT...');
      } else if ((symbolTree.counts.functions || 0) === 0 && (symbolTree.counts.classes || 0) === 0) {
        addEvent('warn', 'No symbols found. Deep analysis might be required.');
      } else {
        addEvent(
          'success',
          `Workstation synced: ${symbolTree.counts.functions || 0} functions, ${symbolTree.counts.classes || 0} classes, ${symbolTree.counts.imports || 0} imports`
        );
      }
      
    } catch (err) {
      console.error('Forensic data load failed:', err);
      addEvent('error', `Workstation synchronization failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  const mapSymbolNode = (node: GhidraSymbolNode, forceOpen: boolean = false): FileNode => ({
    id: node.id,
    name: node.name,
    type: node.type === 'namespace' ? 'namespace' : node.type,
    data: {
      ...node.data,
      address: node.address ?? node.data?.address,
      backend_type: node.type
    },
    isOpen: forceOpen || node.depth <= 1,
    children: node.children?.map(child => mapSymbolNode(child)) || []
  });

  const buildExplorerTree = (
    symbolTree: GhidraSymbolTree,
    memory: GhidraMemorySection[],
    structure: any
  ): FileNode[] => {
    const packageName = structure?.apk_analysis?.package_name || 'AndroidManifest.xml';
    const programTree: FileNode = {
      id: 'program-tree',
      name: 'PROGRAM STRUCTURE',
      type: 'folder',
      isOpen: true,
      children: [
        {
          id: 'mem-map',
          name: 'Memory Map',
          type: 'folder',
          children: memory.map(m => ({
            id: `mem-${m.name}`,
            name: `${m.name} (${m.permissions})`,
            type: 'section',
            data: m
          }))
        },
        { id: 'manifest', name: packageName, type: 'manifest', data: structure?.apk_analysis || {} }
      ]
    };

    const liveSymbolTree: FileNode = {
      id: 'symbol-tree',
      name: 'LIVE SYMBOL EXPLORER',
      type: 'folder',
      isOpen: true,
      data: { counts: symbolTree.counts },
      children: symbolTree.roots.map(node => mapSymbolNode(node, true))
    };

    return [programTree, liveSymbolTree];
  };

  const isDecompilableNode = (node: FileNode) => {
    const address = node.data?.address;
    return (
      ['method', 'function', 'export'].includes(node.type) &&
      Boolean(address) &&
      node.data?.decompilable !== false &&
      !String(address).toUpperCase().startsWith('EXTERNAL:')
    );
  };

  const findNodeById = (nodes: FileNode[], id: string): FileNode | null => {
    for (const node of nodes) {
      if (node.id === id) return node;
      const child = node.children ? findNodeById(node.children, id) : null;
      if (child) return child;
    }
    return null;
  };

  const findFirstDecompilableNode = (nodes: FileNode[]): FileNode | null => {
    for (const node of nodes) {
      if (isDecompilableNode(node)) return node;
      const child = node.children ? findFirstDecompilableNode(node.children) : null;
      if (child) return child;
    }
    return null;
  };

  useEffect(() => {
    if (!selectedNode && !loading && treeData.length > 0 && !autoSelectionAttempted) {
      const fallback = findFirstDecompilableNode(treeData);
      if (fallback) {
        addEvent('info', `Selecting first available decompilable symbol from loaded tree: ${fallback.name}`);
        void handleNodeSelect(fallback);
      } else {
        addEvent('warn', 'No decompilable symbol exists in the current explorer tree after initial load.');
      }
      setAutoSelectionAttempted(true);
    }
  }, [selectedNode, loading, treeData, autoSelectionAttempted]);

  const handleNodeSelect = async (node: FileNode) => {
    console.debug('handleNodeSelect:', node);
    setSelectedNode(node);
    setDecompiledCode(null);
    setCodeInsight(null);
    setDisassembly(null);
    setCrossReferences({ calledBy: [], calls: [] });

    if (isDecompilableNode(node) && activeEvidenceId) {
      try {
        setIsDecompiling(true);
        addEvent('info', `Decompiling: ${node.name} at ${node.data.address}`);
        const code = await decompileFunction(activeEvidenceId, node.data.address);
        console.debug('decompileFunction result:', code);
        setDecompiledCode(code);
        if (!code || !code.c_code) {
          addEvent('warn', `Decompiled symbol returned empty content: ${node.name}`);
        } else {
          addEvent('success', `Decompilation complete: ${node.name}`);
          setActiveCenterTab('DECOMPILER');
          void loadCodeInsight(node, code);
        }
        
        // Load disassembly and xrefs in parallel
        setIsLoadingDisassembly(true);
        setIsLoadingXrefs(true);
        try {
          const [disasm, xrefs] = await Promise.all([
            getDisassembly(activeEvidenceId, node.data.address),
            getCrossReferences(activeEvidenceId, node.data.address)
          ]);
          setDisassembly(disasm);
          if (xrefs && xrefs.length > 0) {
            const calledBy = xrefs.filter(x => x.to_address === node.data.address);
            const calls = xrefs.filter(x => x.from_address === node.data.address);
            setCrossReferences({ calledBy, calls });
          }
        } catch (err) {
          console.warn('Failed to load disassembly or xrefs:', err);
        } finally {
          setIsLoadingDisassembly(false);
          setIsLoadingXrefs(false);
        }
      } catch (err) {
        console.error('Decompilation failed:', err);
        addEvent('error', `Failed to decompile symbol: ${node.name}`);
        setDecompiledCode({
          function_name: node.name,
          address: node.data.address,
          c_code: `// DECOMPILATION FAILED FOR ${node.name}\n// Address: ${node.data.address}\n// The symbol might not be a valid function or the decompiler timed out.`,
          signature: '',
          variables: [],
          calls_to: [],
          called_by: []
        });
      } finally {
        setIsDecompiling(false);
      }
    } else if (node.type === 'import') {
      setDecompiledCode(null);
      addEvent('info', `Selected external import: ${node.name}`);
    } else if (node.type === 'string') {
      setDecompiledCode(null);
      addEvent('info', `Selected string at ${node.data?.address || 'unknown address'}`);
    }
  };

  const loadCodeInsight = async (node: FileNode, code: DecompiledCode) => {
    if (!code?.c_code || !activeEvidenceId) {
      setCodeInsight(null);
      return;
    }

    try {
      setIsExplainingCode(true);
      const analysis = scan?.analysis_result || {};
      const response = await aiApi.explain({
        code: code.c_code,
        scan_id: activeEvidenceId,
        function_name: code.function_name || node.name,
        context: {
          symbol_type: node.type,
          address: code.address,
          class_name: node.data?.class_name,
          package_name: analysis.package_name || analysis.apk_analysis?.package_name,
        },
      });
      setCodeInsight(response);
      if (response.ai_powered === false && response.interpretation?.status === 'unavailable') {
        addEvent('warn', `AI context unavailable for ${node.name}`, 'AI');
      } else {
        addEvent('success', `AI interpretation ready for ${node.name}`, 'AI');
      }
    } catch (error: any) {
      console.warn('AI code interpretation failed', error);
      const errorMsg = error.response?.data?.detail || error.message || 'Request failed';
      setCodeInsight({
        ai_powered: false,
        explanation: `AI interpretation failed: ${errorMsg}`,
        health: {},
        function_name: node.name,
        interpretation: {
          status: 'unavailable',
          purpose: 'AI Unavailable.',
          behavior: 'AI Unavailable.',
          security_impact: 'AI Unavailable.',
          fraud_impact: 'AI Unavailable.',
          confidence: 0,
          evidence: [],
        },
      });
      addEvent('error', `AI interpretation failed for ${node.name}: ${errorMsg}`, 'AI');
    } finally {
      setIsExplainingCode(false);
    }
  };

  if (loading) {
    return (
      <div className="sentinel-mono sentinel-mono-shell h-screen flex items-center justify-center bg-black text-white">
        <div className="relative">
          <div className="w-24 h-24 border-b-2 border-secondary rounded-full animate-spin"></div>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="material-symbols-outlined text-[32px] animate-pulse">biotech</span>
          </div>
          <div className="mt-8 text-center">
            <div className="font-mono text-[10px] uppercase tracking-[0.3em] text-secondary/60 animate-pulse">Initializing OS...</div>
          </div>
        </div>
      </div>
    );
  }

  const analysisPayload = scan?.analysis_result || {};
  const attackMappings = (
    analysisPayload.attack_mapping ||
    analysisPayload.ai_analysis?.attack_mapping ||
    []
  ).filter((item: any) => item?.technique_id && item.technique_id !== 'T0000');
  const interpretation = codeInsight?.interpretation;

  return (
    <div className="sentinel-mono sentinel-mono-shell h-[calc(100vh-64px)] bg-black text-white overflow-hidden flex flex-col font-sans">
      {/* 1. STATUS & DIAGNOSTICS BAR */}
      <DiagnosticBanner diagnostics={diagnostics} metadata={scan} />

      {/* 2. COMPACT FORENSIC TOOLBAR */}
      <div className="mono-panel h-12 bg-black/90 border-b border-white/10 flex items-center px-4 justify-between shrink-0 z-20">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-secondary/10 rounded flex items-center justify-center border border-secondary/20 shadow-[0_0_15px_rgba(var(--secondary-rgb),0.1)]">
              <span className="material-symbols-outlined text-secondary text-[20px]">terminal</span>
            </div>
            <div className="flex flex-col">
              <span className="text-[11px] font-bold tracking-widest text-secondary uppercase leading-none">SENTINEL AI</span>
              <span className="text-[9px] text-on-surface-variant font-mono mt-1 opacity-50 uppercase tracking-tighter">Forensic OS v2.0.4</span>
            </div>
          </div>

          <div className="h-6 w-px bg-white/10"></div>

          <div className="flex items-center gap-1.5 bg-black/30 rounded-full px-1 py-1 border border-white/5">
            <button 
              onClick={() => setMode('CODE_BROWSER')}
              className={cn(
                "px-4 py-1 text-[10px] font-bold rounded-full transition-all duration-300", 
                mode === 'CODE_BROWSER' ? "bg-secondary text-on-secondary shadow-[0_0_15px_rgba(var(--secondary-rgb),0.4)]" : "text-on-surface-variant hover:text-on-surface"
              )}
            >CODE BROWSER</button>
            <button 
              onClick={() => setMode('DEBUGGER')}
              className={cn(
                "px-4 py-1 text-[10px] font-bold rounded-full transition-all duration-300", 
                mode === 'DEBUGGER' ? "bg-error text-white shadow-[0_0_15px_rgba(var(--error-rgb),0.4)]" : "text-on-surface-variant hover:text-on-surface"
              )}
            >DEBUGGER</button>
          </div>

          <div className="mono-oath hidden xl:flex h-8 items-center gap-3 px-3 text-[9px] font-mono uppercase tracking-[0.18em] text-white/70">
            <span className="material-symbols-outlined text-[16px] text-white">shield_lock</span>
            <span className="text-white font-bold">Truth survives obfuscation</span>
            <span className="text-white/35">verify the unseen</span>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="flex flex-col items-end">
            <div className="flex items-center gap-2">
               <span className="text-[10px] font-mono text-on-surface-variant uppercase opacity-50 tracking-tighter">OS STATE:</span>
               <div className="flex items-center gap-1.5">
                  <div className={cn(
                    "w-1.5 h-1.5 rounded-full animate-pulse",
                    diagnostics?.status === 'READY' || diagnostics?.status === 'CONNECTED' ? "bg-success" :
                    ['CONNECTING', 'IMPORTING', 'ANALYZING', 'INDEXING', 'DEGRADED'].includes(diagnostics?.status || '') ? "bg-tertiary" :
                    "bg-error"
                  )}></div>
                  <span className={cn(
                    "text-[10px] font-mono font-bold uppercase",
                    diagnostics?.status === 'READY' || diagnostics?.status === 'CONNECTED' ? "text-success" :
                    ['CONNECTING', 'IMPORTING', 'ANALYZING', 'INDEXING', 'DEGRADED'].includes(diagnostics?.status || '') ? "text-tertiary" :
                    "text-error"
                  )}>
                    {diagnostics?.status || 'OFFLINE'}
                  </span>
               </div>
            </div>
            <span className="text-[9px] font-mono text-secondary opacity-70 mt-0.5">
              {scan?.original_filename || activeEvidenceId?.slice(0, 12)}
            </span>
          </div>
          
          <div className="h-6 w-px bg-white/10"></div>
          
          <div className="flex items-center bg-black/40 border border-white/10 rounded-md px-3 h-8 group focus-within:border-secondary/50 transition-all">
            <span className="material-symbols-outlined text-[18px] opacity-30 group-focus-within:text-secondary transition-colors">search</span>
            <input 
              type="text" 
              placeholder="Search symbols, addresses, strings..." 
              className="bg-transparent border-none outline-none text-[11px] w-64 font-mono ml-2 placeholder:opacity-30"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* 2. MAIN WORKSPACE */}
      <div className="flex-1 overflow-hidden relative">
        <PanelGroup direction="horizontal" className="h-full">
          {/* LEFT: SYMBOL EXPLORER */}
          <Panel defaultSize={18} minSize={15} maxSize={30} className="mono-panel bg-black/85 flex flex-col z-10">
            <VirtualizedExplorer
              treeData={treeData}
              onNodeSelect={(node) => { void handleNodeSelect(node) }}
              selectedNodeId={selectedNode?.id}
              symbolCounts={symbolCounts}
              isLoading={loading}
              searchQuery={searchQuery}
            />
          </Panel>

          <PanelResizeHandle className="w-1 bg-transparent group relative">
            <div className="absolute inset-0 bg-white/[0.02] hover:bg-secondary/20 transition-colors cursor-col-resize"></div>
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-0.5 h-8 bg-white/10 rounded-full group-hover:bg-secondary/50"></div>
          </PanelResizeHandle>

          {/* CENTER: PRIMARY ANALYSIS VIEW */}
          <Panel defaultSize={ mode === 'CODE_BROWSER' ? 57 : 62 } minSize={30} className="mono-panel bg-black/90 flex flex-col z-10">
            <div className="h-9 bg-white/[0.02] border-b border-white/5 flex items-center px-2 shrink-0">
              <div className="flex items-center gap-1 h-full">
                {mode === 'CODE_BROWSER' ? (
                  <>
                    <button 
                      onClick={() => setActiveCenterTab('DECOMPILER')}
                      className={cn(
                        "h-full px-4 flex items-center gap-2 transition-all relative group",
                        activeCenterTab === 'DECOMPILER' ? "text-secondary" : "text-on-surface-variant/50 hover:text-on-surface"
                      )}
                    >
                      <span className="material-symbols-outlined text-[16px]">code</span>
                      <span className="text-[10px] font-mono font-bold tracking-tight uppercase">{selectedNode?.name || 'Listing'}.c</span>
                      {activeCenterTab === 'DECOMPILER' && (
                        <div className="absolute bottom-0 left-2 right-2 h-0.5 bg-secondary shadow-[0_0_10px_rgba(var(--secondary-rgb),0.6)]"></div>
                      )}
                    </button>

                    <button 
                      onClick={() => setActiveCenterTab('DISASSEMBLY')}
                      className={cn(
                        "h-full px-4 flex items-center gap-2 transition-all relative group",
                        activeCenterTab === 'DISASSEMBLY' ? "text-tertiary" : "text-on-surface-variant/50 hover:text-on-surface"
                      )}
                    >
                      <span className="material-symbols-outlined text-[16px]">terminal</span>
                      <span className="text-[10px] font-mono font-bold tracking-tight uppercase">Disassembly</span>
                      {activeCenterTab === 'DISASSEMBLY' && (
                        <div className="absolute bottom-0 left-2 right-2 h-0.5 bg-tertiary shadow-[0_0_10px_rgba(var(--tertiary-rgb),0.6)]"></div>
                      )}
                    </button>
                  </>
                ) : (
                  ['OVERVIEW', 'STACK', 'REGISTERS', 'MEMORY', 'CALL_GRAPH'].map((tab) => {
                    const title = tab === 'CALL_GRAPH' ? 'Call Graph' : tab.charAt(0) + tab.slice(1).toLowerCase();
                    const isActive = activeCenterTab === tab;
                    return (
                      <button
                        key={tab}
                        onClick={() => setActiveCenterTab(tab as any)}
                        className={cn(
                          "h-full px-4 flex items-center gap-2 transition-all relative group",
                          isActive ? "text-secondary" : "text-on-surface-variant/50 hover:text-on-surface"
                        )}
                      >
                        <span className="material-symbols-outlined text-[16px]">monitor_heart</span>
                        <span className="text-[10px] font-mono font-bold tracking-tight uppercase">{title}</span>
                        {isActive && (
                          <div className="absolute bottom-0 left-2 right-2 h-0.5 bg-secondary shadow-[0_0_10px_rgba(var(--secondary-rgb),0.6)]"></div>
                        )}
                      </button>
                    )
                  })
                )}

                 <div className="h-4 w-px bg-white/10 mx-2"></div>

                 <div className="flex items-center gap-2 text-[10px] font-mono text-on-surface-variant/30">
                    {mode === 'CODE_BROWSER' ? (
                      <>
                        {selectedNode?.data?.package && (
                          <span className="hover:text-secondary cursor-pointer transition-colors">{selectedNode.data.package}</span>
                        )}
                        {selectedNode && <span>/</span>}
                        <span className="text-on-surface-variant/60">{selectedNode?.name || 'Select a symbol'}</span>
                      </>
                    ) : (
                      <>
                        <span>{debugState?.execution_status || 'Debugger'}</span>
                        <span>/</span>
                        <span>{debugState?.loaded_module || 'No module loaded'}</span>
                      </>
                    )}
                 </div>

                 {mode === 'CODE_BROWSER' && activeCenterTab === 'DECOMPILER' && decompiledCode?.c_code && (
                   <div className="ml-auto flex items-center gap-2">
                     <button
                       onClick={() => selectedNode && loadCodeInsight(selectedNode, decompiledCode)}
                       disabled={isExplainingCode}
                       className="flex items-center gap-1.5 px-3 py-1 bg-secondary/10 hover:bg-secondary/20 text-secondary border border-secondary/30 rounded text-[9px] font-bold uppercase tracking-wider transition-all disabled:opacity-50"
                     >
                       <span className={`material-symbols-outlined text-[14px] ${isExplainingCode ? 'animate-spin' : ''}`}>
                         {isExplainingCode ? 'sync' : 'psychology'}
                       </span>
                       {isExplainingCode ? 'Analyzing...' : 'Explain Function'}
                     </button>
                   </div>
                 )}
              </div>
            </div>
            
            <div className="flex-1 relative p-2">
              {isDecompiling && (
                <div className="absolute inset-0 z-30 bg-black/60 flex items-center justify-center backdrop-blur-[2px]">
                  <div className="text-center">
                    <div className="w-10 h-10 border-2 border-secondary/20 border-t-secondary rounded-full animate-spin mx-auto mb-4"></div>
                    <div className="font-mono text-[10px] text-secondary uppercase tracking-[0.2em] shadow-lg">Decompiling Artifact...</div>
                  </div>
                </div>
              )}
              
              <div className="h-full rounded-lg overflow-hidden border border-white/10 bg-black">
                {mode === 'CODE_BROWSER' ? (
                  activeCenterTab === 'DECOMPILER' ? (
                    <Editor
                      height="100%"
                      language="cpp"
                      theme="sentinel-mono"
                      value={
                        decompiledCode?.c_code ||
                        (selectedNode
                          ? isDecompilableNode(selectedNode)
                            ? (isDecompiling ? '// Decompiling symbol...' : `// Decompiler returned no source for ${selectedNode.name}`)
                            : `// Select a function, method, or export in the explorer to render code.`
                          : '// WAITING FOR SYMBOL SELECTION FROM EXPLORER...')
                      }
                      beforeMount={(monaco) => {
                        monaco.editor.defineTheme('sentinel-mono', {
                          base: 'vs-dark',
                          inherit: false,
                          rules: [
                            { token: '', foreground: 'f5f5f5', background: '050505' },
                            { token: 'comment', foreground: '8a8a8a', fontStyle: 'italic' },
                            { token: 'keyword', foreground: 'ffffff', fontStyle: 'bold' },
                            { token: 'number', foreground: 'd8d8d8' },
                            { token: 'string', foreground: 'cfcfcf' },
                            { token: 'type', foreground: 'ffffff' }
                          ],
                          colors: {
                            'editor.background': '#050505',
                            'editor.foreground': '#f5f5f5',
                            'editorLineNumber.foreground': '#555555',
                            'editorLineNumber.activeForeground': '#ffffff',
                            'editor.selectionBackground': '#ffffff2a',
                            'editor.lineHighlightBackground': '#ffffff0b',
                            'editorCursor.foreground': '#ffffff',
                            'editorWhitespace.foreground': '#333333'
                          }
                        });
                      }}
                      options={{
                        readOnly: true,
                        minimap: { enabled: true, side: 'right', scale: 1 },
                        fontSize: 14,
                        lineHeight: 22,
                        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                        lineNumbers: 'on',
                        scrollBeyondLastLine: false,
                        automaticLayout: true,
                        padding: { top: 20, bottom: 20 },
                        renderLineHighlight: 'all',
                        folding: true,
                        glyphMargin: true,
                        lineDecorationsWidth: 15,
                        cursorBlinking: 'smooth',
                        smoothScrolling: true,
                        scrollbar: {
                          vertical: 'visible',
                          horizontal: 'visible',
                          useShadows: false,
                          verticalScrollbarSize: 10,
                          horizontalScrollbarSize: 10
                        }
                      }}
                      onMount={(editor) => { editorRef.current = editor; }}
                    />
                  ) : (
                    <DisassemblyView
                      disassembly={disassembly}
                      isLoading={isLoadingDisassembly}
                      error={disassembly?.instructions.length === 0 ? 'No disassembly available' : undefined}
                    />
                  )
                ) : (
                  <div className="h-full overflow-hidden bg-black/95 text-on-surface">
                    {(isLoadingDebugState || isLoadingCallGraph) && (
                      <div className="absolute inset-0 z-20 bg-black/70 flex items-center justify-center">
                        <div className="text-center">
                          <div className="w-12 h-12 border-2 border-secondary/20 border-t-secondary rounded-full animate-spin mx-auto mb-3"></div>
                          <div className="text-[10px] font-mono uppercase text-secondary">Loading debugger runtime...</div>
                        </div>
                      </div>
                    )}

                    {!debugState && !isLoadingDebugState ? (
                      <div className="flex h-full items-center justify-center text-on-surface-variant/40">
                        <div className="text-center">
                          <span className="material-symbols-outlined text-[48px] mb-2 opacity-20">bug_report</span>
                          <p className="text-[11px] font-mono uppercase tracking-[0.18em]">Debugger state unavailable</p>
                        </div>
                      </div>
                    ) : (
                      <>
                        {activeCenterTab === 'OVERVIEW' && (
                          <div className="h-full overflow-y-auto p-4 space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                              <div className="border border-white/10 rounded-lg p-4 bg-white/5">
                                <div className="text-[9px] uppercase text-on-surface-variant/60 mb-2">Execution</div>
                                <div className="text-[20px] font-bold text-secondary">{debugState?.execution_status || 'PAUSED'}</div>
                                <div className="text-[10px] text-on-surface-variant mt-2">Active thread: {debugState?.active_thread || 'unknown'}</div>
                                <div className="text-[10px] text-on-surface-variant">PC: {debugState?.program_counter || 'n/a'}</div>
                              </div>
                              <div className="border border-white/10 rounded-lg p-4 bg-white/5">
                                <div className="text-[9px] uppercase text-on-surface-variant/60 mb-2">Module</div>
                                <div className="text-[20px] font-bold text-primary">{debugState?.loaded_module || 'No module loaded'}</div>
                                <div className="text-[10px] text-on-surface-variant mt-2">Threads: {debugState?.threads.length || 0}</div>
                                <div className="text-[10px] text-on-surface-variant">Breakpoints: {debugState?.breakpoints.length || 0}</div>
                              </div>
                            </div>
                            <div className="border border-white/10 rounded-lg p-4 bg-white/5">
                              <div className="text-[9px] uppercase text-on-surface-variant/60 mb-2">Recent Debugger Events</div>
                              <div className="space-y-2 text-[11px] font-mono">
                                {debugState?.logs.slice(0, 5).map((log, idx) => (
                                  <div key={idx} className="text-on-surface-variant">• {log}</div>
                                ))}
                              </div>
                            </div>
                          </div>
                        )}

                        {activeCenterTab === 'STACK' && <StackVisualization debugState={debugState} />}

                        {activeCenterTab === 'REGISTERS' && <RegisterVisualization debugState={debugState} />}

                        {activeCenterTab === 'MEMORY' && <MemoryVisualization debugState={debugState} />}

                        {activeCenterTab === 'CALL_GRAPH' && <CallGraphVisualization callGraph={callGraph} />}
                      </>
                    )}
                  </div>
                )}
              </div>
            </div>
          </Panel>

          <PanelResizeHandle className="w-1 bg-transparent group relative">
            <div className="absolute inset-0 bg-white/[0.02] hover:bg-secondary/20 transition-colors cursor-col-resize"></div>
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-0.5 h-8 bg-white/10 rounded-full group-hover:bg-secondary/50"></div>
          </PanelResizeHandle>

          {/* RIGHT: AI + THREAT INTELLIGENCE */}
          <Panel defaultSize={25} minSize={20} maxSize={35} className="mono-panel bg-black/85 flex flex-col z-10">
            <div className="h-9 bg-white/[0.02] border-b border-white/5 flex items-center px-4 justify-between shrink-0 flex-wrap">
               <span className="text-[10px] font-bold text-on-surface-variant uppercase tracking-[0.15em]">Intelligence Matrix</span>
            </div>
            
            <div className="flex-1 overflow-y-auto custom-scrollbar p-3 space-y-4">
              {/* Symbol Metadata */}
              <div className="border border-white/10 rounded bg-white/[0.02]">
                <div className="h-7 bg-white/[0.03] border-b border-white/5 px-3 flex items-center">
                  <span className="text-[9px] font-bold text-on-surface-variant uppercase tracking-widest">Symbol Details</span>
                </div>
                <div className="p-2">
                  <SymbolMetadataPanel
                    selectedNode={selectedNode}
                    decompiledCode={decompiledCode}
                    isLoading={isDecompiling}
                    onCopyAddress={(addr) => {
                      navigator.clipboard.writeText(addr);
                      addEvent('success', `Copied address: ${addr}`);
                    }}
                  />
                </div>
              </div>

              {/* Cross-References */}
              <div className="border border-white/10 rounded bg-white/[0.02]">
                <div className="h-7 bg-white/[0.03] border-b border-white/5 px-3 flex items-center">
                  <span className="text-[9px] font-bold text-on-surface-variant uppercase tracking-widest">Cross-References</span>
                </div>
                <div className="p-2">
                  <CrossReferencesPanel
                    references={crossReferences}
                    isLoading={isLoadingXrefs}
                    onReferenceClick={(address, name) => {
                      const node = findNodeById(treeData, `sym_${address}`);
                      if (node) {
                        handleNodeSelect(node);
                        addEvent('info', `Navigated to ${name}`);
                      }
                    }}
                  />
                </div>
              </div>

              <IntelligenceCard
                title="Code Interpretation"
                icon="psychology"
                badge={isExplainingCode ? 'ANALYZING' : `${interpretation?.confidence ?? 0}% CONF`}
                badgeType={interpretation?.status === 'available' ? 'success' : 'warn'}
              >
                <div className="flex justify-between items-center mb-2 px-1">
                  <span className="text-[8px] font-bold text-on-surface-variant/60 uppercase tracking-widest">Source: AI Interpretation</span>
                  <span className={`text-[8px] font-bold uppercase tracking-widest ${
                    (interpretation?.confidence ?? 0) >= 75 ? 'text-success' : 
                    (interpretation?.confidence ?? 0) >= 40 ? 'text-warning' : 
                    'text-error'
                  }`}>
                    {(interpretation?.confidence ?? 0) >= 75 ? 'High' : (interpretation?.confidence ?? 0) >= 40 ? 'Medium' : 'Low'} Confidence
                  </span>
                </div>
                {isExplainingCode ? (
                  <div className="flex items-center gap-2 text-[11px] text-on-surface-variant">
                    <span className="material-symbols-outlined text-sm animate-spin">sync</span>
                    Interpreting selected source...
                  </div>
                ) : interpretation ? (
                  <div className="space-y-3">
                    {[
                      ['Purpose', interpretation.purpose],
                      ['Behavior', interpretation.behavior],
                      ['Security Impact', interpretation.security_impact],
                      ['Fraud Impact', interpretation.fraud_impact],
                      ['Risk Contribution', interpretation.risk_contribution ? `+${interpretation.risk_contribution}` : undefined],
                      ['Confidence', interpretation.confidence ? `${interpretation.confidence}%` : undefined],
                    ].map(([label, value]) => value && (
                      <div key={label} className="border border-white/5 bg-white/[0.03] rounded p-2">
                        <p className="text-[9px] font-bold text-secondary uppercase tracking-widest mb-1">{label}</p>
                        <p className="text-[11px] text-on-surface-variant leading-relaxed">{value}</p>
                      </div>
                    ))}
                    {interpretation.evidence && interpretation.evidence.length > 0 && (
                      <div className="border-t border-white/10 pt-2 space-y-1">
                        <p className="text-[9px] font-bold text-on-surface-variant uppercase tracking-widest">Evidence</p>
                        {interpretation.evidence.slice(0, 5).map((item: string, index: number) => (
                          <p key={index} className="text-[9px] text-on-surface-variant/70 truncate select-text">
                            &gt; {item}
                          </p>
                        ))}
                      </div>
                    )}
                    {codeInsight?.explanation && (
                      <p className="text-[10px] text-on-surface-variant/70 leading-relaxed border-l border-secondary/30 pl-2">
                        {codeInsight.explanation}
                      </p>
                    )}
                  </div>
                ) : (
                  <p className="text-[11px] text-on-surface-variant/70 leading-relaxed">
                    Select a decompilable function or method to generate a source-backed interpretation.
                  </p>
                )}
              </IntelligenceCard>

              <IntelligenceCard title="MITRE ATT&CK" icon="grid_view" badge={attackMappings.length} badgeType="warn">
                <div className="flex justify-between items-center mb-2 px-1">
                  <span className="text-[8px] font-bold text-on-surface-variant/60 uppercase tracking-widest">Source: Static + Heuristics</span>
                  <span className="text-[8px] font-bold text-warning uppercase tracking-widest">Medium Confidence</span>
                </div>
                <div className="space-y-2">
                  {attackMappings.length === 0 ? (
                    <p className="text-[11px] text-on-surface-variant/70 leading-relaxed">
                      No ATT&CK mappings are stored for this artifact yet.
                    </p>
                  ) : (
                    attackMappings.map((item: any) => (
                      <div key={`${item.technique_id}-${item.category}`} className="p-2 bg-white/[0.03] border border-white/5 rounded">
                        <p className="text-[10px] font-bold text-secondary">{item.technique_id}: {item.technique_name}</p>
                        <p className="text-[9px] text-on-surface-variant uppercase opacity-50">
                          {item.category} / {item.confidence ?? 0}% CONF
                        </p>
                        {item.matched_tokens?.length > 0 && (
                          <p className="text-[9px] text-on-surface-variant/70 mt-1 truncate">
                            {item.matched_tokens.join(', ')}
                          </p>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </IntelligenceCard>
            </div>
          </Panel>
        </PanelGroup>
      </div>

      {/* 3. ANALYST CONSOLE (BOTTOM PANEL) */}
      <div className="mono-panel h-48 bg-black/90 border-t border-white/10 flex flex-col shrink-0 z-20">
        <div className="h-8 bg-white/[0.02] border-b border-white/5 flex items-center px-4 justify-between">
          <div className="flex gap-1 h-full">
            {['CONSOLE', 'MCP LOGS', 'DEBUGGER', 'CROSS-REFS', 'NETWORK'].map(tab => (
              <button 
                key={tab}
                onClick={() => setActiveBottomTab(tab)}
                className={cn(
                  "text-[9px] font-bold h-full px-4 transition-all relative group uppercase tracking-widest",
                  activeBottomTab === tab ? "text-secondary" : "text-on-surface-variant/40 hover:text-on-surface"
                )}
              >
                {tab}
                {activeBottomTab === tab && (
                  <div className="absolute bottom-0 left-2 right-2 h-0.5 bg-secondary shadow-[0_0_10px_rgba(var(--secondary-rgb),0.6)]"></div>
                )}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-6 text-[9px] font-mono">
            <div className="flex items-center gap-2">
              <span className="text-on-surface-variant uppercase opacity-40">Symbols:</span>
              <span className="text-secondary font-bold">{symbolCounts.nodes || 0}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-on-surface-variant uppercase opacity-40">Functions:</span>
              <span className="text-success font-bold">{symbolCounts.functions || 0}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-on-surface-variant uppercase opacity-40">Engine:</span>
              <span className="text-primary font-bold">{diagnostics?.connected ? 'GHIDRA MCP' : 'OFFLINE'}</span>
            </div>
          </div>
        </div>
        
        <div className="flex-1 overflow-y-auto p-3 font-mono text-[11px] space-y-1 custom-scrollbar bg-black/40">
          {activeBottomTab === 'CONSOLE' && events.map((event, i) => (
            <div key={i} className="flex gap-4 group hover:bg-white/[0.03] px-2 py-0.5 rounded transition-colors">
              <span className="text-on-surface-variant opacity-30 shrink-0">[{event.timestamp}]</span>
              <span className={cn(
                "shrink-0 w-12 font-bold uppercase tracking-tighter",
                event.level === 'info' ? "text-primary" :
                event.level === 'warn' ? "text-tertiary" :
                event.level === 'error' ? "text-error" :
                "text-success"
              )}>{event.level}</span>
              <span className="text-on-surface-variant opacity-40 shrink-0">[{event.source}]</span>
              <span className="text-on-surface/90">{event.message}</span>
            </div>
          ))}
          {activeBottomTab === 'DEBUGGER' ? (
            <div className="space-y-3 text-[11px]">
              {debugState?.logs.length ? (
                debugState.logs.map((log, idx) => (
                  <div key={idx} className="border border-white/10 rounded px-3 py-2 text-on-surface-variant bg-black/20">
                    <span className="font-mono">{log}</span>
                  </div>
                ))
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-on-surface-variant/30">
                  <span className="material-symbols-outlined text-[48px] mb-2 opacity-20">bug_report</span>
                  <p className="text-[10px] uppercase tracking-[0.2em]">No debugger logs yet</p>
                </div>
              )}
            </div>
          ) : activeBottomTab !== 'CONSOLE' ? (
            <div className="h-full flex flex-col items-center justify-center text-on-surface-variant/20 italic select-none">
               <span className="material-symbols-outlined text-[48px] mb-2 opacity-10">monitoring</span>
               <p className="text-[10px] uppercase tracking-[0.2em]">{activeBottomTab} data not yet collected for this symbol.</p>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
};

export default CodeAnalysisPage;
