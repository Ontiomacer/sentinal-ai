/**
 * Cross-References Panel for Symbol Navigation
 */

import React, { memo } from 'react'
import { CrossReference } from '../services/ghidraApi'

interface CrossReferencesPanelProps {
  references: {
    calledBy: CrossReference[]
    calls: CrossReference[]
  }
  isLoading: boolean
  onReferenceClick?: (address: string, name: string) => void
}

const CrossReferencesPanel: React.FC<CrossReferencesPanelProps> = memo(({
  references,
  isLoading,
  onReferenceClick
}) => {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-32 text-on-surface-variant/50">
        <span className="material-symbols-outlined text-4xl animate-spin opacity-30">sync</span>
      </div>
    )
  }

  const hasReferences = references.calledBy.length > 0 || references.calls.length > 0

  return (
    <div className="space-y-4">
      {/* Called By Section */}
      <div>
        <div className="px-3 py-2 bg-white/[0.03] border-b border-white/10 flex items-center justify-between">
          <span className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">
            CALLED BY ({references.calledBy.length})
          </span>
          <span className="material-symbols-outlined text-[16px] opacity-40">arrow_inward</span>
        </div>
        {references.calledBy.length > 0 ? (
          <div className="space-y-1 p-2">
            {references.calledBy.map((ref, idx) => (
              <CrossReferenceItem
                key={`called-by-${idx}`}
                reference={ref}
                onClick={() => onReferenceClick?.(ref.from_address, ref.from_name)}
              />
            ))}
          </div>
        ) : (
          <div className="text-[11px] text-on-surface-variant/30 p-2 italic">No incoming references</div>
        )}
      </div>

      {/* Calls Section */}
      <div>
        <div className="px-3 py-2 bg-white/[0.03] border-b border-white/10 flex items-center justify-between">
          <span className="text-[10px] font-bold uppercase tracking-widest text-on-surface-variant">
            CALLS ({references.calls.length})
          </span>
          <span className="material-symbols-outlined text-[16px] opacity-40">arrow_outward</span>
        </div>
        {references.calls.length > 0 ? (
          <div className="space-y-1 p-2">
            {references.calls.map((ref, idx) => (
              <CrossReferenceItem
                key={`calls-${idx}`}
                reference={ref}
                onClick={() => onReferenceClick?.(ref.to_address, ref.to_name)}
              />
            ))}
          </div>
        ) : (
          <div className="text-[11px] text-on-surface-variant/30 p-2 italic">No outgoing references</div>
        )}
      </div>

      {!hasReferences && (
        <div className="text-center py-6 text-on-surface-variant/30">
          <span className="material-symbols-outlined text-4xl block mb-2 opacity-20">link_off</span>
          <span className="text-xs font-mono">No cross-references available</span>
        </div>
      )}
    </div>
  )
})

interface CrossReferenceItemProps {
  reference: CrossReference
  onClick?: () => void
}

const CrossReferenceItem: React.FC<CrossReferenceItemProps> = memo(({ reference, onClick }) => {
  const getTypeColor = (type: string) => {
    switch (type) {
      case 'call':
        return 'text-secondary'
      case 'jump':
        return 'text-tertiary'
      case 'reference':
        return 'text-primary'
      case 'data':
        return 'text-success'
      default:
        return 'text-on-surface-variant'
    }
  }

  return (
    <div
      onClick={onClick}
      className="p-2 bg-white/[0.02] border border-white/5 rounded hover:bg-white/[0.08] hover:border-white/20 transition-all cursor-pointer group"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="font-mono text-[10px] text-on-surface-variant/60 truncate">{reference.to_address}</div>
          <div className={`text-[11px] font-bold truncate ${getTypeColor(reference.type)}`}>
            {reference.to_name}
          </div>
        </div>
        <span className={`text-[9px] font-mono px-1.5 py-0.5 bg-white/5 rounded shrink-0 ${getTypeColor(reference.type)}`}>
          {reference.type.toUpperCase()}
        </span>
      </div>
    </div>
  )
})

CrossReferencesPanel.displayName = 'CrossReferencesPanel'
CrossReferenceItem.displayName = 'CrossReferenceItem'

export default CrossReferencesPanel
