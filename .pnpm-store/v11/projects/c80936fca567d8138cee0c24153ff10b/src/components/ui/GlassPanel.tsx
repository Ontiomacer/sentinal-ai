import { ReactNode, HTMLAttributes } from 'react'

interface GlassPanelProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode
  className?: string
  glow?: boolean
}

const GlassPanel = ({ children, className = '', glow = false, ...props }: GlassPanelProps) => {
  return (
    <div className={`glass-panel rounded-xl ${glow ? 'neural-glow' : ''} ${className}`} {...props}>
      {children}
    </div>
  )
}

export default GlassPanel
