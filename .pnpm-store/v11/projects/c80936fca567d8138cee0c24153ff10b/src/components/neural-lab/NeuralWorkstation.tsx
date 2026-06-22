import { ReactNode } from 'react'
import GlassPanel from '../ui/GlassPanel'

interface NeuralWorkstationProps {
  commandBar: ReactNode
  tabs: ReactNode
  activity?: ReactNode
  navigator: ReactNode
  sidebar: ReactNode
  children: ReactNode
}

const NeuralWorkstation = ({
  commandBar,
  tabs,
  activity,
  navigator,
  sidebar,
  children,
}: NeuralWorkstationProps) => {
  return (
    <div className="workstation-panel border-glow">
      <div className="workstation-panel-header justify-between">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-[18px] text-on-surface">developer_board</span>
          <span>NEURAL WORKSTATION</span>
        </div>
        <span>GHIDRA STYLE MULTI-PANEL VIEW</span>
      </div>

      <div className="p-4 border-b border-white/5">
        {commandBar}
      </div>

      {activity && (
        <div className="p-4 border-b border-white/5 bg-black/20">
          {activity}
        </div>
      )}

      <div className="p-4 border-b border-white/5">
        {tabs}
      </div>

      <div className="grid grid-cols-1 2xl:grid-cols-[280px_minmax(0,1fr)_320px] xl:grid-cols-[240px_minmax(0,1fr)] min-h-[720px]">
        <aside className="border-r border-white/5 bg-black/20 p-4 space-y-4">
          {navigator}
        </aside>

        <main className="p-4 xl:p-6 min-w-0">
          <GlassPanel className="mono-panel p-4 min-h-full">
            {children}
          </GlassPanel>
        </main>

        <aside className="border-l border-white/5 bg-black/20 p-4 2xl:block xl:hidden">
          {sidebar}
        </aside>
      </div>

      <div className="2xl:hidden border-t border-white/5 p-4 bg-black/20">
        {sidebar}
      </div>
    </div>
  )
}

export default NeuralWorkstation
