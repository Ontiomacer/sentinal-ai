/**
 * Symbol Metadata Inspector Panel
 */

import React, { memo } from 'react'
import { DecompiledCode } from '../services/ghidraApi'

interface FileNode {
  id: string
  name: string
  type: string
  children?: FileNode[]
  data?: any
  isOpen?: boolean
}

interface SymbolMetadataProps {
  selectedNode: FileNode | null
  decompiledCode: DecompiledCode | null
  isLoading: boolean
  onCopyAddress?: (address: string) => void
}

const SymbolMetadataPanel: React.FC<SymbolMetadataProps> = memo(({
  selectedNode,
  decompiledCode,
  isLoading,
  onCopyAddress
}) => {
  if (!selectedNode) {
    return (
      <div className="flex items-center justify-center h-full text-on-surface-variant/30">
        <div className="text-center">
          <span className="material-symbols-outlined text-4xl mb-2 block opacity-20">info</span>
          <span className="text-xs font-mono">Select a symbol to view metadata</span>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4 p-3">
      {/* Symbol Name & Type */}
      <div className="border border-white/10 rounded p-3 bg-white/[0.02]">
        <div className="text-[9px] uppercase text-on-surface-variant/60 font-mono tracking-widest mb-1">
          Symbol
        </div>
        <div className="text-[12px] font-bold text-primary break-all mb-2">
          {selectedNode.name}
        </div>
        <div className="inline-block text-[9px] px-2 py-1 bg-white/5 border border-white/10 rounded font-mono text-on-surface-variant/70">
          {selectedNode.type.toUpperCase()}
        </div>
      </div>

      {/* Address */}
      {selectedNode.data?.address && (
        <div className="border border-white/10 rounded p-3 bg-white/[0.02]">
          <div className="text-[9px] uppercase text-on-surface-variant/60 font-mono tracking-widest mb-2">
            Address
          </div>
          <div className="flex items-center justify-between gap-2">
            <code className="text-[11px] font-bold text-tertiary bg-black/30 px-2 py-1 rounded flex-1 overflow-x-auto">
              {selectedNode.data.address}
            </code>
            <button
              onClick={() => onCopyAddress?.(selectedNode.data?.address!)}
              className="flex items-center justify-center w-6 h-6 rounded hover:bg-white/10 transition-colors text-on-surface-variant/70 hover:text-on-surface"
              title="Copy address"
            >
              <span className="material-symbols-outlined text-[16px]">content_copy</span>
            </button>
          </div>
        </div>
      )}

      {/* Namespace & Class */}
      {(selectedNode.data?.namespace || selectedNode.data?.class_name) && (
        <div className="border border-white/10 rounded p-3 bg-white/[0.02]">
          <div className="text-[9px] uppercase text-on-surface-variant/60 font-mono tracking-widest mb-2">
            Classification
          </div>
          <div className="space-y-1">
            {selectedNode.data?.namespace && (
              <div>
                <div className="text-[9px] text-on-surface-variant/60 mb-0.5">Namespace</div>
                <code className="text-[10px] text-secondary bg-black/30 px-2 py-1 rounded block overflow-x-auto">
                  {selectedNode.data.namespace}
                </code>
              </div>
            )}
            {selectedNode.data?.class_name && (
              <div>
                <div className="text-[9px] text-on-surface-variant/60 mb-0.5">Class</div>
                <code className="text-[10px] text-secondary bg-black/30 px-2 py-1 rounded block overflow-x-auto">
                  {selectedNode.data.class_name}
                </code>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Signature (from decompilation) */}
      {decompiledCode?.signature && (
        <div className="border border-white/10 rounded p-3 bg-white/[0.02]">
          <div className="text-[9px] uppercase text-on-surface-variant/60 font-mono tracking-widest mb-2">
            Signature
          </div>
          <code className="text-[10px] text-on-surface bg-black/30 px-2 py-1 rounded block font-mono whitespace-pre-wrap break-words">
            {decompiledCode.signature}
          </code>
        </div>
      )}

      {/* Size (if available) */}
      {selectedNode.data?.size && (
        <div className="border border-white/10 rounded p-3 bg-white/[0.02]">
          <div className="text-[9px] uppercase text-on-surface-variant/60 font-mono tracking-widest mb-2">
            Size
          </div>
          <div className="text-[11px] font-mono text-success">
            {typeof selectedNode.data.size === 'number'
              ? `${selectedNode.data.size} bytes (0x${selectedNode.data.size.toString(16)})`
              : selectedNode.data.size}
          </div>
        </div>
      )}

      {/* Data */}
      {selectedNode.data && Object.keys(selectedNode.data).length > 0 && (
        <div className="border border-white/10 rounded p-3 bg-white/[0.02]">
          <div className="text-[9px] uppercase text-on-surface-variant/60 font-mono tracking-widest mb-2">
            Metadata
          </div>
          <div className="space-y-1 text-[9px] font-mono">
            {Object.entries(selectedNode.data)
              .filter(([k]) => !['size', 'namespace', 'class_name'].includes(k))
              .map(([key, value]) => (
                <div key={key} className="flex justify-between gap-2 text-on-surface-variant/70">
                  <span className="text-on-surface-variant/50">{key}:</span>
                  <span className="text-on-surface/70 truncate">{String(value).substring(0, 40)}</span>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Decompilation Status */}
      {isLoading && (
        <div className="border border-primary/30 rounded p-3 bg-primary/5">
          <div className="flex items-center gap-2 text-[11px] text-primary">
            <span className="material-symbols-outlined text-[16px] animate-spin">hourglass_empty</span>
            Decompiling...
          </div>
        </div>
      )}
    </div>
  )
})

SymbolMetadataPanel.displayName = 'SymbolMetadataPanel'

export default SymbolMetadataPanel
