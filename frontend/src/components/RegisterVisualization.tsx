import React, { useState, useEffect } from 'react';
import { GhidraDebugState } from '../services/ghidraApi';
import { cn } from '../utils/cn';

interface RegisterVisualizationProps {
  debugState: GhidraDebugState | null;
  onRegisterClick?: (register: any) => void;
}

/**
 * Graphical Register Visualization
 * 
 * Renders an interactive register state display showing:
 * - Register values (Dalvik v0-vN, p0-pN)
 * - Value transitions and changes
 * - Live updates with animations
 * - Register group organization
 */
export const RegisterVisualization: React.FC<RegisterVisualizationProps> = ({
  debugState,
  onRegisterClick
}) => {
  const [selectedReg, setSelectedReg] = useState<string | null>(null);
  const [regHistory, setRegHistory] = useState<Record<string, string[]>>({});

  const registers = debugState?.registers || [];

  // Track register value changes
  useEffect(() => {
    setRegHistory(prev => {
      const updated = { ...prev };
      registers.forEach(reg => {
        if (!updated[reg.name]) {
          updated[reg.name] = [];
        }
        if (updated[reg.name][0] !== reg.value) {
          updated[reg.name] = [reg.value, ...updated[reg.name].slice(0, 4)];
        }
      });
      return updated;
    });
  }, [registers]);

  const formatValue = (value: string): string => {
    if (!value) return 'N/A';
    try {
      const num = parseInt(value, 16);
      return `0x${num.toString(16).toUpperCase().padStart(8, '0')}`;
    } catch {
      return value;
    }
  };

  const getRegisterGroup = (name: string): 'general' | 'special' | 'dalvik' => {
    if (name.startsWith('v')) return 'dalvik';
    if (name.startsWith('p')) return 'dalvik';
    if (['RSP', 'RBP', 'RIP', 'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI'].includes(name.toUpperCase())) {
      return 'general';
    }
    return 'special';
  };

  const getRegisterColor = (name: string): string => {
    const group = getRegisterGroup(name);
    if (group === 'general') return 'from-secondary/20 to-secondary/5';
    if (group === 'dalvik') return 'from-primary/20 to-primary/5';
    return 'from-tertiary/20 to-tertiary/5';
  };

  const getGroupTitle = (group: 'general' | 'special' | 'dalvik'): string => {
    switch (group) {
      case 'general': return 'General Purpose';
      case 'dalvik': return 'Dalvik VM Registers';
      case 'special': return 'Special Purpose';
    }
  };

  // Group registers
  const generalRegs = registers.filter(r => getRegisterGroup(r.name) === 'general');
  const dalvikRegs = registers.filter(r => getRegisterGroup(r.name) === 'dalvik');
  const specialRegs = registers.filter(r => getRegisterGroup(r.name) === 'special');

  if (registers.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-on-surface-variant/40">
        <div className="text-center">
          <span className="material-symbols-outlined text-[48px] mb-2 opacity-20">memory</span>
          <p className="text-[11px] font-mono uppercase tracking-[0.18em]">No registers available</p>
        </div>
      </div>
    );
  }

  const RegisterGroup = ({ title, regs }: { title: string; regs: typeof registers }) => (
    <div className="border border-white/10 rounded-lg bg-white/5 p-4 space-y-3">
      <div className="text-[10px] font-bold uppercase text-on-surface-variant/60 tracking-[0.1em]">
        {title}
      </div>

      <div className="grid grid-cols-2 gap-3">
        {regs.map(reg => {
          const isSelected = selectedReg === reg.name;
          const prev = regHistory[reg.name]?.[1];
          const changed = prev && prev !== reg.value;

          return (
            <div
              key={reg.name}
              className={cn(
                "p-3 rounded-lg border transition-all cursor-pointer group",
                isSelected
                  ? "border-secondary/50 bg-secondary/10 ring-2 ring-secondary/30 shadow-lg"
                  : "border-white/10 bg-gradient-to-br hover:border-white/20 hover:bg-white/[0.08]",
                getRegisterColor(reg.name)
              )}
              onClick={() => {
                setSelectedReg(reg.name);
                onRegisterClick?.(reg);
              }}
            >
              {/* REGISTER NAME */}
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] font-bold text-on-surface">{reg.name}</span>
                {changed && (
                  <span className="material-symbols-outlined text-[14px] text-tertiary animate-pulse">
                    trending_up
                  </span>
                )}
              </div>

              {/* REGISTER VALUE */}
              <div className="space-y-1">
                <div className="text-[10px] font-mono text-primary font-bold break-all">
                  {formatValue(reg.value)}
                </div>

                {/* PREVIOUS VALUE (IF CHANGED) */}
                {changed && (
                  <div className="text-[9px] font-mono text-on-surface-variant/50">
                    was: {formatValue(prev)}
                  </div>
                )}
              </div>

              {/* BINARY REPRESENTATION */}
              <div className="mt-2 pt-2 border-t border-white/5 text-[8px] text-on-surface-variant/40 font-mono">
                {(() => {
                  try {
                    const num = parseInt(reg.value, 16);
                    return num.toString(2).padStart(32, '0').slice(-32);
                  } catch {
                    return 'N/A';
                  }
                })()}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );

  return (
    <div className="h-full flex flex-col gap-4 p-4 overflow-y-auto">
      {/* HEADER */}
      <div className="flex items-center justify-between">
        <div className="text-[10px] font-bold uppercase text-on-surface-variant/60 tracking-[0.1em]">
          Processor State
        </div>
        <div className="text-[9px] text-on-surface-variant/40 font-mono">
          {registers.length} register{registers.length !== 1 ? 's' : ''}
        </div>
      </div>

      {/* REGISTER GROUPS */}
      <div className="space-y-4 flex-1">
        {dalvikRegs.length > 0 && (
          <RegisterGroup title={getGroupTitle('dalvik')} regs={dalvikRegs} />
        )}

        {generalRegs.length > 0 && (
          <RegisterGroup title={getGroupTitle('general')} regs={generalRegs} />
        )}

        {specialRegs.length > 0 && (
          <RegisterGroup title={getGroupTitle('special')} regs={specialRegs} />
        )}
      </div>

      {/* SELECTED REGISTER DETAILS */}
      {selectedReg && registers.find(r => r.name === selectedReg) && (
        <div className="border-t border-white/10 pt-4 mt-auto">
          <div className="text-[10px] font-bold uppercase text-on-surface-variant/60 mb-3 tracking-[0.1em]">
            Register Details: {selectedReg}
          </div>

          <div className="space-y-2">
            <div className="bg-black/40 rounded-lg p-3 border border-white/10">
              <div className="text-[9px] text-on-surface-variant/60 mb-1">Hexadecimal</div>
              <div className="font-mono text-[11px] text-secondary font-bold">
                {formatValue(registers.find(r => r.name === selectedReg)?.value || 'N/A')}
              </div>
            </div>

            <div className="bg-black/40 rounded-lg p-3 border border-white/10">
              <div className="text-[9px] text-on-surface-variant/60 mb-1">Decimal</div>
              <div className="font-mono text-[11px] text-primary">
                {(() => {
                  try {
                    return parseInt(registers.find(r => r.name === selectedReg)?.value || '0', 16);
                  } catch {
                    return 'N/A';
                  }
                })()}
              </div>
            </div>

            <div className="bg-black/40 rounded-lg p-3 border border-white/10">
              <div className="text-[9px] text-on-surface-variant/60 mb-1">Binary (32-bit)</div>
              <div className="font-mono text-[10px] text-tertiary break-all">
                {(() => {
                  try {
                    const num = parseInt(registers.find(r => r.name === selectedReg)?.value || '0', 16);
                    return num.toString(2).padStart(32, '0');
                  } catch {
                    return 'N/A';
                  }
                })()}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RegisterVisualization;
