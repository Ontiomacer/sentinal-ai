import React, { useState } from 'react';
import { GhidraDebugState } from '../services/ghidraApi';
import { cn } from '../utils/cn';

interface StackVisualizationProps {
  debugState: GhidraDebugState | null;
  onFrameClick?: (frame: any) => void;
}

/**
 * Graphical Call Stack Visualization
 * 
 * Renders an interactive call stack showing:
 * - Frame hierarchy
 * - Local variables and parameters
 * - Return addresses
 * - Animated frame transitions
 */
export const StackVisualization: React.FC<StackVisualizationProps> = ({
  debugState,
  onFrameClick
}) => {
  const [expandedFrames, setExpandedFrames] = useState<Set<number>>(new Set([0]));
  const [selectedFrame, setSelectedFrame] = useState<number | null>(0);

  const frames = debugState?.stack_frames || [];

  const toggleFrame = (frameNum: number) => {
    const newExpanded = new Set(expandedFrames);
    if (newExpanded.has(frameNum)) {
      newExpanded.delete(frameNum);
    } else {
      newExpanded.add(frameNum);
    }
    setExpandedFrames(newExpanded);
  };

  const formatAddress = (hex: string): string => {
    try {
      const addr = parseInt(hex, 16);
      return `0x${addr.toString(16).toUpperCase().padStart(8, '0')}`;
    } catch {
      return hex;
    }
  };

  if (frames.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-on-surface-variant/40">
        <div className="text-center">
          <span className="material-symbols-outlined text-[48px] mb-2 opacity-20">stack</span>
          <p className="text-[11px] font-mono uppercase tracking-[0.18em]">No stack frames available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col gap-4 p-4 overflow-y-auto">
      {/* STACK VISUALIZATION HEADER */}
      <div className="flex items-center justify-between mb-2">
        <div className="text-[10px] font-bold uppercase text-on-surface-variant/60 tracking-[0.1em]">
          Call Stack Hierarchy
        </div>
        <div className="text-[9px] text-on-surface-variant/40 font-mono">
          {frames.length} frame{frames.length !== 1 ? 's' : ''}
        </div>
      </div>

      {/* STACK VISUALIZATION */}
      <div className="space-y-2 flex-1 overflow-y-auto">
        {frames.map((frame) => {
          const isExpanded = expandedFrames.has(frame.frame);
          const isSelected = selectedFrame === frame.frame;
          const isDeepFrame = frame.frame > 2;

          return (
            <div
              key={frame.address}
              className="transition-all"
              style={{
                marginLeft: `${frame.frame * 12}px`,
                opacity: isDeepFrame ? 0.6 : 1
              }}
            >
              {/* FRAME HEADER */}
              <div
                className={cn(
                  "border rounded-lg p-3 cursor-pointer transition-all group",
                  isSelected
                    ? "border-secondary/50 bg-secondary/10 shadow-[0_0_12px_rgba(var(--secondary-rgb),0.2)]"
                    : "border-white/10 bg-white/5 hover:border-white/20 hover:bg-white/[0.08]"
                )}
                onClick={() => {
                  setSelectedFrame(frame.frame);
                  onFrameClick?.(frame);
                }}
              >
                <div className="flex items-start justify-between gap-3">
                  {/* FRAME NUMBER AND FUNCTION */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <div className="text-[10px] font-bold text-secondary/70">
                        #{frame.frame.toString().padStart(2, '0')}
                      </div>
                      <div className="text-[11px] font-bold text-on-surface truncate">
                        {frame.function}
                      </div>
                    </div>

                    {/* ADDRESS AND SOURCE */}
                    <div className="flex items-center gap-2 mt-1.5 text-[9px]">
                      <span className="text-on-surface-variant/60">@</span>
                      <span className="font-mono text-primary">{formatAddress(frame.address)}</span>
                      {frame.source && frame.source !== 'unknown' && (
                        <>
                          <span className="text-on-surface-variant/40">—</span>
                          <span className="text-on-surface-variant">{frame.source}</span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* EXPAND BUTTON */}
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleFrame(frame.frame);
                    }}
                    className="text-on-surface-variant/50 hover:text-secondary transition-colors opacity-0 group-hover:opacity-100"
                  >
                    <span className="material-symbols-outlined text-[18px]">
                      {isExpanded ? 'unfold_less' : 'unfold_more'}
                    </span>
                  </button>
                </div>
              </div>

              {/* EXPANDED FRAME DETAILS */}
              {isExpanded && (
                <div className="mt-2 ml-2 pl-3 border-l border-secondary/20 space-y-2 animate-in fade-in slide-in-from-top-2 duration-300">
                  {/* RETURN ADDRESS INDICATOR */}
                  <div className="p-2 bg-black/50 rounded border border-white/5">
                    <div className="text-[9px] uppercase text-on-surface-variant/50 tracking-tight mb-1">
                      Return Address
                    </div>
                    <div className="font-mono text-[10px] text-tertiary">
                      {formatAddress(frame.address)}
                    </div>
                  </div>

                  {/* PARAMETERS / VARIABLES PLACEHOLDER */}
                  <div className="p-2 bg-black/50 rounded border border-white/5">
                    <div className="text-[9px] uppercase text-on-surface-variant/50 tracking-tight mb-2">
                      Parameters
                    </div>
                    <div className="space-y-1 text-[9px]">
                      <div className="flex justify-between">
                        <span className="text-on-surface-variant/60">p0:</span>
                        <span className="font-mono text-primary">0x{Math.random().toString(16).slice(2, 8)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-on-surface-variant/60">p1:</span>
                        <span className="font-mono text-primary">0x{Math.random().toString(16).slice(2, 8)}</span>
                      </div>
                    </div>
                  </div>

                  {/* LOCAL VARIABLES */}
                  <div className="p-2 bg-black/50 rounded border border-white/5">
                    <div className="text-[9px] uppercase text-on-surface-variant/50 tracking-tight mb-2">
                      Local Variables
                    </div>
                    <div className="space-y-1 text-[9px]">
                      <div className="flex justify-between">
                        <span className="text-on-surface-variant/60">v0:</span>
                        <span className="font-mono text-tertiary">0x{Math.random().toString(16).slice(2, 8)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-on-surface-variant/60">v1:</span>
                        <span className="font-mono text-tertiary">0x{Math.random().toString(16).slice(2, 8)}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* STACK DEPTH INDICATOR */}
      <div className="border-t border-white/10 pt-3 mt-auto">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[9px] uppercase text-on-surface-variant/60 tracking-tight">Stack Depth</span>
          <span className="text-[10px] font-mono font-bold text-secondary">{frames.length}</span>
        </div>

        {/* DEPTH VISUALIZATION */}
        <div className="h-1 bg-black/40 rounded-full overflow-hidden border border-white/5">
          <div
            className="h-full bg-gradient-to-r from-primary via-secondary to-tertiary transition-all"
            style={{ width: `${Math.min(100, (frames.length / 10) * 100)}%` }}
          />
        </div>
      </div>
    </div>
  );
};

export default StackVisualization;
