/**
 * Symbol Search and Filter Utilities
 */

import { GhidraSymbolNode } from '../services/ghidraApi'

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

export const searchSymbols = (
  symbols: GhidraSymbolNode[],
  query: string,
  typeFilter?: string[]
): GhidraSymbolNode[] => {
  if (!query && !typeFilter) return symbols
  
  const lowerQuery = query.toLowerCase()
  return symbols.filter(sym => {
    const matchesQuery = !query || sym.name.toLowerCase().includes(lowerQuery)
    const matchesType = !typeFilter || typeFilter.includes(sym.type)
    return matchesQuery && matchesType
  })
}

// Group symbols by namespace for hierarchical display
export const groupSymbolsByNamespace = (symbols: GhidraSymbolNode[]): Record<string, GhidraSymbolNode[]> => {
  const groups: Record<string, GhidraSymbolNode[]> = {}
  
  symbols.forEach(sym => {
    const namespace = sym.data?.namespace || sym.name.split('::')[0] || 'Other'
    if (!groups[namespace]) {
      groups[namespace] = []
    }
    groups[namespace].push(sym)
  })
  
  return groups
}

// Group symbols by type
export const groupSymbolsByType = (symbols: GhidraSymbolNode[]): Record<string, GhidraSymbolNode[]> => {
  const groups: Record<string, GhidraSymbolNode[]> = {}
  
  symbols.forEach(sym => {
    const type = sym.type || 'unknown'
    if (!groups[type]) {
      groups[type] = []
    }
    groups[type].push(sym)
  })
  
  return groups
}

// Sort symbols intelligently
export const sortSymbols = (symbols: GhidraSymbolNode[], sortBy: 'name' | 'address' | 'type' = 'name'): GhidraSymbolNode[] => {
  const sorted = [...symbols]
  
  sorted.sort((a, b) => {
    switch (sortBy) {
      case 'address':
        return (a.address || '').localeCompare(b.address || '')
      case 'type':
        return (a.type || '').localeCompare(b.type || '')
      case 'name':
      default:
        return (a.name || '').toLowerCase().localeCompare((b.name || '').toLowerCase())
    }
  })
  
  return sorted
}
