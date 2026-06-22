import { ReactNode } from 'react'
import GlassPanel from './GlassPanel'

interface NeuralVisualizationProps {
  children?: ReactNode
  confidence?: number
  tags?: string[]
  insights?: Array<{ title: string; description: string }>
}

const NeuralVisualization = ({ 
  children, 
  confidence, 
  tags = [], 
  insights = [] 
}: NeuralVisualizationProps) => {
  return (
    <GlassPanel glow className="relative aspect-video overflow-hidden flex items-center justify-center">
      {/* Background visualization placeholder */}
      <div className="absolute inset-0 opacity-40 bg-gradient-to-br from-surface-container via-surface to-surface-container-high">
        {children}
      </div>

      {/* Interactive Overlay Components */}
      <div className="relative z-10 w-full h-full p-12 flex flex-col justify-between">
        <div className="flex justify-between items-start">
          {confidence !== undefined && (
            <GlassPanel className="p-4 flex flex-col gap-1">
              <span className="text-on-surface-variant font-label-sm text-label-sm uppercase tracking-tighter">
                COGNITIVE CONFIDENCE
              </span>
              <span className="text-tertiary font-display-xl text-title-md">
                {confidence.toFixed(2)}%
              </span>
            </GlassPanel>
          )}
          
          {tags.length > 0 && (
            <div className="flex flex-col items-end gap-2">
              <div className="flex gap-2 flex-wrap justify-end">
                {tags.map((tag, index) => (
                  <span
                    key={index}
                    className="px-3 py-1 glass-panel border-error/50 text-error font-label-sm text-label-sm"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {insights.length > 0 && (
          <div className="grid grid-cols-3 gap-8">
            {insights.map((insight, index) => (
              <div key={index} className="flex flex-col gap-2">
                <span className="text-on-surface-variant font-label-sm text-label-sm border-b border-white/5 pb-2 uppercase">
                  {insight.title}
                </span>
                <p className="text-on-surface opacity-80 text-label-sm font-label-sm">
                  {insight.description}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Scanline Effect */}
      <div className="absolute inset-0 scanline pointer-events-none opacity-20"></div>
    </GlassPanel>
  )
}

export default NeuralVisualization
