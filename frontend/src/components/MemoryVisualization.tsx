import React, { useState } from 'react';
import { GhidraMemorySection, GhidraDebugState } from '../services/ghidraApi';
import { cn } from '../utils/cn';

interface MemoryVisualizationProps {
  debugState: GhidraDebugState | null;
  memoryRegions?: GhidraMemorySection[];
  onRegionClick?: (region: any) => void;
}

/**
 * Interactive Memory Map Visualization
 * 
 * Renders a graphical representation of memory layout with:
 * - Address space visualization
 * - Color-coded memory regions
 * - Interactive clickable segments
 * - Forensic annotations
 */
export const MemoryVisualization: React.FC<MemoryVisualizationProps> = ({
  debugState,
  memoryRegions,
  onRegionClick
}) => {
  const [hoveredRegion, setHoveredRegion] = useState<string | null>(null);
  const [selectedRegion, setSelectedRegion] = useState<string | null>(null);

  const regions = debugState?.memory_regions || memoryRegions || [];

  // Calculate address space (simplified)
  const maxAddress = Math.max(...regions.map(r => {
    const end = r.end || r.start;
    return parseInt(end, 16) || 0;
  }), 0x1000000);

  const minAddress = Math.min(...regions.map(r => parseInt(r.start, 16) || 0), 0);

  const addressRange = maxAddress - minAddress || 0x1000000;

  const getRegionColor = (region: any): string => {
    const perms = (region.permissions || '').toLowerCase();
    const name = (region.name || '').toUpperCase();

    if (name.includes('STACK')) return '#ef5350'; // Red
    if (name.includes('HEAP')) return '#42a5f5'; // Blue
    if (name.includes('CODE') || name.includes('TEXT')) return '#66bb6a'; // Green
    if (name.includes('STRING')) return '#ffa726'; // Orange
    if (perms.includes('x')) return '#66bb6a'; // Executable - Green
    if (perms.includes('w')) return '#42a5f5'; // Writable - Blue
    if (perms.includes('r')) return '#ab47bc'; // Readable - Purple
    return '#bdbdbd'; // Other - Gray
  };

  const getRegionHeight = (region: any): number => {
    try {
      const start = parseInt(region.start, 16) || 0;
      const end = parseInt(region.end, 16) || 0;
      const size = end - start;
      return Math.max(20, (size / addressRange) * 400);
    } catch {
      return 40;
    }
  };

  const formatAddress = (hex: string): string => {
    try {
      const addr = parseInt(hex, 16);
      return `0x${addr.toString(16).toUpperCase().padStart(8, '0')}`;
    } catch {
      return hex;
    }
  };

  const formatSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  };

  return (
    <div className="h-full flex flex-col gap-4 p-4">
      {/* MEMORY MAP VISUALIZATION */}
      <div className="flex-1 flex gap-4">
        {/* GRAPHICAL MEMORY MAP */}
        <div className="flex-1 border border-white/10 rounded-lg bg-black/40 p-4 overflow-y-auto">
          <div className="text-[10px] font-bold uppercase text-on-surface-variant/60 mb-4 tracking-[0.1em]">
            Address Space Layout
          </div>

          <div className="flex flex-col gap-1">
            {regions.map((region) => {
              const height = getRegionHeight(region);
              const color = getRegionColor(region);
              const isHovered = hoveredRegion === region.name;
              const isSelected = selectedRegion === region.name;

              return (
                <div
                  key={region.name}
                  className={cn(
                    "relative rounded-md cursor-pointer transition-all group overflow-hidden",
                    isHovered || isSelected ? "ring-2 ring-secondary shadow-lg" : "hover:ring-1 hover:ring-white/20"
                  )}
                  style={{
                    height: `${height}px`,
                    backgroundColor: color,
                    opacity: isHovered || isSelected ? 0.9 : 0.7
                  }}
                  onMouseEnter={() => setHoveredRegion(region.name)}
                  onMouseLeave={() => setHoveredRegion(null)}
                  onClick={() => {
                    setSelectedRegion(region.name);
                    onRegionClick?.(region);
                  }}
                >
                  {/* REGION LABEL */}
                  <div className="absolute inset-0 flex flex-col items-start justify-center px-3 py-2 pointer-events-none">
                    <div className="text-[10px] font-bold text-white/90 uppercase tracking-tight">
                      {region.name}
                    </div>
                    <div className="text-[9px] text-white/70 font-mono mt-1">
                      {formatAddress(region.start)}
                    </div>
                  </div>

                  {/* HOVER TOOLTIP */}
                  {isHovered && (
                    <div className="absolute inset-0 flex items-center justify-center bg-black/20 backdrop-blur-sm">
                      <div className="bg-black/90 border border-white/20 rounded px-3 py-2 text-[9px] text-center">
                        <div className="font-bold text-secondary mb-1">{region.name}</div>
                        <div className="text-on-surface-variant">
                          {formatAddress(region.start)} → {formatAddress(region.end)}
                        </div>
                        <div className="text-on-surface-variant/70">
                          Size: {formatSize(region.size || 0)}
                        </div>
                        <div className="text-on-surface-variant/70">
                          {region.permissions}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* MEMORY STATISTICS PANEL */}
        <div className="w-64 flex flex-col gap-3">
          {/* SELECTED REGION DETAILS */}
          {selectedRegion && (
            <div className="border border-white/10 rounded-lg bg-white/5 p-3">
              <div className="text-[9px] uppercase text-on-surface-variant/60 mb-2 tracking-[0.1em]">
                Selected Region
              </div>
              {regions.find(r => r.name === selectedRegion) && (
                <div className="space-y-2 text-[10px]">
                  <div>
                    <span className="text-on-surface-variant/60">Name:</span>
                    <span className="text-secondary ml-2 font-bold">{selectedRegion}</span>
                  </div>
                  <div>
                    <span className="text-on-surface-variant/60">Start:</span>
                    <span className="text-primary ml-2 font-mono">{formatAddress(regions.find(r => r.name === selectedRegion)?.start || '')}</span>
                  </div>
                  <div>
                    <span className="text-on-surface-variant/60">End:</span>
                    <span className="text-primary ml-2 font-mono">{formatAddress(regions.find(r => r.name === selectedRegion)?.end || '')}</span>
                  </div>
                  <div>
                    <span className="text-on-surface-variant/60">Size:</span>
                    <span className="text-tertiary ml-2 font-bold">
                      {formatSize(regions.find(r => r.name === selectedRegion)?.size || 0)}
                    </span>
                  </div>
                  <div>
                    <span className="text-on-surface-variant/60">Perms:</span>
                    <span className="text-on-surface ml-2 font-mono">
                      {regions.find(r => r.name === selectedRegion)?.permissions}
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* LEGEND */}
          <div className="border border-white/10 rounded-lg bg-white/5 p-3">
            <div className="text-[9px] uppercase text-on-surface-variant/60 mb-3 tracking-[0.1em]">
              Memory Legend
            </div>
            <div className="space-y-2">
              {[
                { name: 'STACK', color: '#ef5350' },
                { name: 'HEAP', color: '#42a5f5' },
                { name: 'CODE', color: '#66bb6a' },
                { name: 'STRING', color: '#ffa726' }
              ].map(item => (
                <div key={item.name} className="flex items-center gap-2">
                  <div
                    className="w-3 h-3 rounded"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-[9px] text-on-surface-variant">{item.name}</span>
                </div>
              ))}
            </div>
          </div>

          {/* MEMORY STATS */}
          <div className="border border-white/10 rounded-lg bg-white/5 p-3">
            <div className="text-[9px] uppercase text-on-surface-variant/60 mb-3 tracking-[0.1em]">
              Statistics
            </div>
            <div className="space-y-2 text-[10px]">
              <div className="flex justify-between">
                <span className="text-on-surface-variant/60">Total Regions:</span>
                <span className="text-secondary font-bold">{regions.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-on-surface-variant/60">Total Size:</span>
                <span className="text-primary font-bold">
                  {formatSize(regions.reduce((sum, r) => sum + (r.size || 0), 0))}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-on-surface-variant/60">Active Thread:</span>
                <span className="text-tertiary font-mono">{debugState?.active_thread || 'N/A'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MemoryVisualization;
