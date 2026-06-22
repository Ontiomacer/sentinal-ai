/**
 * Disassembly View Component for Ghidra Analysis
 */

import React, { memo } from 'react'
import { Disassembly, DisassemblyInstruction } from '../services/ghidraApi'

interface DisassemblyViewProps {
  disassembly: Disassembly | null
  isLoading: boolean
  error?: string
}

const DisassemblyView: React.FC<DisassemblyViewProps> = memo(({ disassembly, isLoading, error }) => {
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-on-surface-variant">
        <div className="text-center">
          <div className="animate-spin mb-4">
            <span className="material-symbols-outlined text-4xl opacity-50">hourglass_empty</span>
          </div>
          <span className="text-sm font-mono">Loading disassembly...</span>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full text-error">
        <div className="text-center">
          <span className="material-symbols-outlined text-4xl mb-4 block">warning</span>
          <span className="text-sm font-mono">{error}</span>
        </div>
      </div>
    )
  }

  if (!disassembly || disassembly.instructions.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-on-surface-variant/50">
        <div className="text-center">
          <span className="material-symbols-outlined text-4xl mb-4 block opacity-30">memory</span>
          <span className="text-sm font-mono">No disassembly available</span>
        </div>
      </div>
    )
  }

  return (
    <div className="h-full overflow-y-auto bg-black/40">
      <div className="font-mono text-xs text-on-surface">
        <div className="sticky top-0 bg-black/60 border-b border-white/10 px-4 py-2 text-on-surface-variant/70">
          <div className="grid grid-cols-12 gap-4">
            <div className="col-span-2">ADDRESS</div>
            <div className="col-span-3">BYTES</div>
            <div className="col-span-4">MNEMONIC</div>
            <div className="col-span-3">OPERANDS</div>
          </div>
        </div>

        {disassembly.instructions.map((instr, idx) => (
          <InstructionRow key={`${instr.address}-${idx}`} instruction={instr} />
        ))}
      </div>
    </div>
  )
})

const InstructionRow: React.FC<{ instruction: DisassemblyInstruction }> = memo(({ instruction }) => {
  return (
    <div className="border-b border-white/5 hover:bg-white/5 transition-colors px-4 py-1 cursor-pointer group">
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-2 text-tertiary font-bold">{instruction.address}</div>
        <div className="col-span-3 text-on-surface-variant/70 break-words">{instruction.bytes}</div>
        <div className="col-span-4 text-secondary font-bold">{instruction.mnemonic}</div>
        <div className="col-span-3 text-on-surface-variant text-xs">{instruction.opcode}</div>
      </div>
      {instruction.comment && (
        <div className="text-on-surface-variant/50 italic text-xs mt-1 ml-2">// {instruction.comment}</div>
      )}
    </div>
  )
})

DisassemblyView.displayName = 'DisassemblyView'
InstructionRow.displayName = 'InstructionRow'

export default DisassemblyView
