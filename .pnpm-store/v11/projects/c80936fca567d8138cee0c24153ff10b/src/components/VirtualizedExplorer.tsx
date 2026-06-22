/**
 * Virtualized Symbol Explorer
 * Efficiently renders symbols with collapsible groups and search
 */

import React, { useCallback, useMemo, useState, memo } from 'react'
import { clsx } from 'clsx'

// FileNode interface (same as CodeAnalysisPage)
interface FileNode {
  id: string
  name: string
  type: string
  children?: FileNode[]
  data?: any
  isOpen?: boolean
}

interface VirtualizedExplorerProps {
  treeData: FileNode[]
  onNodeSelect: (node: FileNode) => void
  selectedNodeId?: string
  symbolCounts: Record<string, number>
  isLoading?: boolean
  searchQuery?: string
}

const VirtualizedExplorer: React.FC<VirtualizedExplorerProps> = memo(({
  treeData,
  onNodeSelect,
  selectedNodeId,
  symbolCounts,
  isLoading = false,
  searchQuery: externalSearchQuery = ''
}) => {
  const [internalSearchQuery, setInternalSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<string[]>([])
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set(['function', 'method']))

  const searchQuery = externalSearchQuery || internalSearchQuery

  // Flatten tree structure
  const flattenTree = useCallback((nodes: FileNode[]): FileNode[] => {
    const flattened: FileNode[] = []
    const stack = [...nodes]
    
    while (stack.length > 0) {
      const node = stack.pop()
      if (!node) continue
      flattened.push(node)
      if (node.children?.length) {
        stack.push(...node.children)
      }
    }
    
    return flattened
  }, [])

  // Filter symbols
  const filteredSymbols = useMemo(() => {
    let symbols = flattenTree(treeData)
    
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      symbols = symbols.filter(s => s.name.toLowerCase().includes(q))
    }
    
    if (typeFilter.length > 0) {
      symbols = symbols.filter(s => typeFilter.includes(s.type))
    }
    
    return symbols
  }, [treeData, searchQuery, typeFilter, flattenTree])

  // Group by type
  const groupedSymbols = useMemo(() => {
    if (searchQuery) {
      return { 'Results': filteredSymbols }
    }
    
    const groups: Record<string, FileNode[]> = {}
    filteredSymbols.forEach(sym => {
      const key = sym.type || 'other'
      if (!groups[key]) groups[key] = []
      groups[key].push(sym)
    })
    return groups
  }, [filteredSymbols, searchQuery])

  const toggleGroup = useCallback((type: string) => {
    setExpandedGroups(prev => {
      const next = new Set(prev)
      next.has(type) ? next.delete(type) : next.add(type)
      return next
    })
  }, [])

  const handleSearch = useCallback((value: string) => {
    setInternalSearchQuery(value)
  }, [])

  const toggleTypeFilter = useCallback((type: string) => {
    setTypeFilter(prev => 
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    )
  }, [])

  return (
    <div className="flex flex-col h-full bg-black/20 border-r border-white/10">
      {/* Header */}
      <div className="flex-shrink-0 border-b border-white/10 p-3 space-y-3">
        {/* Search */}
        <div className="relative">
          <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-on-surface-variant/50 pointer-events-none">
            <span className="material-symbols-outlined text-[18px]">search</span>
          </span>
          <input
            type="text"
            placeholder="Search symbols..."
            value={searchQuery}
            onChange={(e) => handleSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-[12px] bg-white/5 border border-white/10 rounded text-on-surface placeholder:text-on-surface-variant/40 focus:outline-none focus:border-primary/50 focus:bg-white/10 transition-all"
          />
        </div>

        {/* Counts */}
        <div className="grid grid-cols-2 gap-2 text-[10px] text-on-surface-variant/70">
          <div className="bg-white/5 rounded px-2 py-1 flex justify-between items-center">
            <span>Functions:</span>
            <span className="font-bold text-primary">{symbolCounts.functions || 0}</span>
          </div>
          <div className="bg-white/5 rounded px-2 py-1 flex justify-between items-center">
            <span>Methods:</span>
            <span className="font-bold text-secondary">{symbolCounts.methods || 0}</span>
          </div>
          <div className="bg-white/5 rounded px-2 py-1 flex justify-between items-center">
            <span>Classes:</span>
            <span className="font-bold text-tertiary">{symbolCounts.classes || 0}</span>
          </div>
          <div className="bg-white/5 rounded px-2 py-1 flex justify-between items-center">
            <span>Imports:</span>
            <span className="font-bold text-success">{symbolCounts.imports || 0}</span>
          </div>
        </div>

        {/* Type filters */}
        <div className="flex flex-wrap gap-1">
          {['function', 'method', 'class', 'import', 'export'].map(type => (
            <button
              key={type}
              onClick={() => toggleTypeFilter(type)}
              className={clsx(
                'text-[9px] px-2 py-1 rounded transition-colors uppercase font-mono',
                typeFilter.includes(type)
                  ? 'bg-primary/30 text-primary border border-primary/50'
                  : 'bg-white/5 text-on-surface-variant/70 border border-white/10 hover:border-white/20'
              )}
            >
              {type}
            </button>
          ))}
        </div>

        {/* Count */}
        <div className="text-[10px] text-on-surface-variant/60 px-1">
          {filteredSymbols.length > 0
            ? `${filteredSymbols.length} symbols`
            : 'No matches'}
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto custom-scrollbar">
        {isLoading ? (
          <div className="flex items-center justify-center h-full text-on-surface-variant/50">
            <div className="text-center">
              <span className="material-symbols-outlined text-4xl animate-spin mb-2 block opacity-30">hourglass_empty</span>
              <span className="text-xs font-mono">Loading...</span>
            </div>
          </div>
        ) : filteredSymbols.length > 0 ? (
          <div className="divide-y divide-white/5">
            {Object.entries(groupedSymbols).map(([type, symbols]) => (
              <SymbolGroup
                key={type}
                type={type}
                symbols={symbols}
                isExpanded={expandedGroups.has(type)}
                onToggle={() => toggleGroup(type)}
                selectedNodeId={selectedNodeId}
                onSelect={onNodeSelect}
              />
            ))}
          </div>
        ) : (
          <div className="flex items-center justify-center h-full text-on-surface-variant/40">
            <span className="text-xs font-mono">No symbols</span>
          </div>
        )}
      </div>
    </div>
  )
})

interface SymbolGroupProps {
  type: string
  symbols: FileNode[]
  isExpanded: boolean
  onToggle: () => void
  selectedNodeId?: string
  onSelect: (node: FileNode) => void
}

const SymbolGroup: React.FC<SymbolGroupProps> = memo(({
  type,
  symbols,
  isExpanded,
  onToggle,
  selectedNodeId,
  onSelect
}) => {
  return (
    <div>
      {/* Group Header */}
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2 px-3 py-1.5 bg-white/5 hover:bg-white/10 transition-colors border-b border-white/5 text-left group"
      >
        <span className={`material-symbols-outlined text-[16px] opacity-60 transition-transform ${isExpanded ? '' : '-rotate-90'}`}>
          expand_more
        </span>
        <span className="text-[11px] font-bold uppercase text-on-surface-variant/70 flex-1">
          {type}
        </span>
        <span className="text-[10px] font-mono text-on-surface-variant/50 group-hover:text-on-surface-variant">
          {symbols.length}
        </span>
      </button>

      {/* Group Items */}
      {isExpanded && (
        <div>
          {symbols.map(node => (
            <SymbolItem
              key={node.id}
              node={node}
              isSelected={node.id === selectedNodeId}
              onSelect={onSelect}
            />
          ))}
        </div>
      )}
    </div>
  )
})

interface SymbolItemProps {
  node: FileNode
  isSelected: boolean
  onSelect: (node: FileNode) => void
}

const SymbolItem: React.FC<SymbolItemProps> = memo(({
  node,
  isSelected,
  onSelect
}) => {
  const typeColor =
    node.type === 'function' ? 'text-primary' :
    node.type === 'method' ? 'text-secondary' :
    node.type === 'class' ? 'text-tertiary' :
    node.type === 'import' ? 'text-success' :
    'text-on-surface-variant'

  return (
    <button
      onClick={() => onSelect(node)}
      className={clsx(
        'w-full flex items-center gap-2 px-4 py-1.5 text-left transition-colors border-b border-white/5 hover:bg-white/5',
        isSelected && 'bg-primary/20 border-primary/30'
      )}
    >
      <span className={`material-symbols-outlined text-[14px] opacity-70 ${typeColor}`}>
        {node.type === 'function' ? 'function' : node.type === 'method' ? 'call_made' : 'description'}
      </span>
      <div className="flex-1 min-w-0">
        <div className={`text-[11px] font-mono font-bold truncate ${typeColor}`}>
          {node.name}
        </div>
        {node.data?.address && (
          <div className="text-[9px] text-on-surface-variant/50 truncate font-mono">
            {node.data.address}
          </div>
        )}
      </div>
    </button>
  )
})

VirtualizedExplorer.displayName = 'VirtualizedExplorer'
SymbolGroup.displayName = 'SymbolGroup'
SymbolItem.displayName = 'SymbolItem'

export default VirtualizedExplorer
