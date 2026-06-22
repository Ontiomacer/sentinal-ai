import { useEffect, useMemo, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import GlassPanel from '../components/ui/GlassPanel'
import {
  CaseFileNode,
  CaseFilesystem,
  CaseResponse,
  CaseTriage,
  getCaseFilesystem,
  getCaseTriage
} from '../services/caseApi'

interface CaseContextType {
  caseData: CaseResponse
}

const formatBytes = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
}

const FileTreeItem = ({
  node,
  level,
  selectedId,
  onSelect
}: {
  node: CaseFileNode
  level: number
  selectedId?: string
  onSelect: (node: CaseFileNode) => void
}) => {
  const [open, setOpen] = useState(level < 2)
  const hasChildren = node.children && node.children.length > 0

  return (
    <div className="select-none">
      <button
        type="button"
        onClick={() => {
          if (hasChildren) setOpen(!open)
          onSelect(node)
        }}
        className={`w-full flex items-center gap-2 px-2 py-1 text-left font-mono text-[11px] transition-colors ${
          selectedId === node.id
            ? 'bg-secondary/10 text-secondary'
            : 'text-on-surface-variant hover:bg-white/5 hover:text-on-surface'
        }`}
        style={{ paddingLeft: `${level * 14 + 8}px` }}
      >
        <span className="material-symbols-outlined text-[14px] opacity-50 w-4">
          {hasChildren ? (open ? 'expand_more' : 'chevron_right') : ''}
        </span>
        <span className="material-symbols-outlined text-[16px] opacity-80">
          {node.kind === 'directory' ? 'folder' : node.evidence_id ? 'fingerprint' : 'description'}
        </span>
        <span className="truncate flex-1">{node.name}</span>
        {node.kind === 'file' && (
          <span className="text-[10px] opacity-45">{formatBytes(node.size)}</span>
        )}
      </button>
      {open && hasChildren && (
        <div>
          {node.children.map(child => (
            <FileTreeItem
              key={child.id}
              node={child}
              level={level + 1}
              selectedId={selectedId}
              onSelect={onSelect}
            />
          ))}
        </div>
      )}
    </div>
  )
}

const CaseFilesPage = () => {
  const { caseData } = useOutletContext<CaseContextType>()
  const [filesystem, setFilesystem] = useState<CaseFilesystem | null>(null)
  const [triage, setTriage] = useState<CaseTriage | null>(null)
  const [selectedNode, setSelectedNode] = useState<CaseFileNode | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true
    const load = async () => {
      try {
        setLoading(true)
        const [fsData, triageData] = await Promise.all([
          getCaseFilesystem(caseData.id),
          getCaseTriage(caseData.id)
        ])
        if (!mounted) return
        setFilesystem(fsData)
        setTriage(triageData)
        setSelectedNode(fsData.tree)
      } finally {
        if (mounted) setLoading(false)
      }
    }
    load()
    const interval = window.setInterval(load, 15000)
    return () => {
      mounted = false
      window.clearInterval(interval)
    }
  }, [caseData.id])

  const directoryRows = useMemo(() => filesystem?.expected_directories || [], [filesystem])

  if (loading && !filesystem) {
    return (
      <GlassPanel className="p-10 text-center">
        <span className="material-symbols-outlined text-5xl text-secondary mb-4 block animate-pulse">
          account_tree
        </span>
        <p className="font-mono text-label-sm text-on-surface-variant uppercase">
          Mounting case filesystem...
        </p>
      </GlassPanel>
    )
  }

  return (
    <div className="fade-in space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-[1.15fr_0.85fr] gap-gutter">
        <GlassPanel className="overflow-hidden">
          <div className="h-10 border-b border-white/10 px-4 flex items-center justify-between bg-black/25">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-secondary">folder_managed</span>
              <span className="font-label-sm text-label-sm uppercase tracking-widest text-on-surface">
                Case Filesystem
              </span>
            </div>
            <span className="font-mono text-[10px] text-on-surface-variant">
              {filesystem ? formatBytes(filesystem.totals.bytes) : '0 B'}
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-[1fr_280px] min-h-[460px]">
            <div className="overflow-y-auto custom-scrollbar py-2 border-r border-white/10">
              {filesystem && (
                <FileTreeItem
                  node={filesystem.tree}
                  level={0}
                  selectedId={selectedNode?.id}
                  onSelect={setSelectedNode}
                />
              )}
            </div>
            <div className="p-4 font-mono text-[11px] space-y-3 bg-black/20">
              <div>
                <div className="text-on-surface-variant uppercase mb-1">Selected</div>
                <div className="text-on-surface break-all">{selectedNode?.relative_path || '.'}</div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="text-on-surface-variant uppercase">Kind</div>
                  <div className="text-secondary">{selectedNode?.kind || 'directory'}</div>
                </div>
                <div>
                  <div className="text-on-surface-variant uppercase">Size</div>
                  <div className="text-secondary">{formatBytes(selectedNode?.size || 0)}</div>
                </div>
              </div>
              {selectedNode?.sha256 && (
                <div>
                  <div className="text-on-surface-variant uppercase mb-1">SHA256</div>
                  <div className="text-on-surface break-all">{selectedNode.sha256}</div>
                </div>
              )}
              {selectedNode?.evidence_id && (
                <div>
                  <div className="text-on-surface-variant uppercase mb-1">Evidence ID</div>
                  <div className="text-on-surface break-all">{selectedNode.evidence_id}</div>
                </div>
              )}
            </div>
          </div>
        </GlassPanel>

        <div className="space-y-6">
          <GlassPanel className="p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-label-sm text-label-sm uppercase tracking-widest text-on-surface">
                CSI Directory Layout
              </h3>
              <span className="font-mono text-[10px] text-on-surface-variant">
                {directoryRows.length} zones
              </span>
            </div>
            <div className="space-y-2">
              {directoryRows.map(directory => (
                <div
                  key={directory.name}
                  className="flex items-center justify-between border border-white/5 bg-black/20 px-3 py-2"
                >
                  <div className="flex items-center gap-2">
                    <span className="material-symbols-outlined text-[16px] text-secondary">
                      {directory.exists ? 'check_circle' : 'error'}
                    </span>
                    <span className="font-mono text-[11px] text-on-surface">{directory.relative_path}</span>
                  </div>
                  <div className="font-mono text-[10px] text-on-surface-variant">
                    {directory.file_count} files / {formatBytes(directory.size)}
                  </div>
                </div>
              ))}
            </div>
          </GlassPanel>

          <GlassPanel className="p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-label-sm text-label-sm uppercase tracking-widest text-on-surface">
                Triage Drives
              </h3>
              <span className="font-mono text-[10px] text-on-surface-variant">
                {triage?.configured_roots_env}
              </span>
            </div>
            <div className="space-y-3">
              {triage?.drives.map(drive => (
                <div key={drive.path} className="border border-white/10 bg-black/25 p-3">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="material-symbols-outlined text-[18px] text-secondary">
                        {drive.is_case_triage ? 'move_to_inbox' : 'hard_drive'}
                      </span>
                      <span className="font-mono text-[11px] text-on-surface">{drive.name}</span>
                    </div>
                    <span className={`font-mono text-[10px] uppercase ${
                      drive.status === 'ready' ? 'text-tertiary' : 'text-error'
                    }`}>
                      {drive.status}
                    </span>
                  </div>
                  <div className="font-mono text-[10px] text-on-surface-variant break-all">
                    {drive.path}
                  </div>
                  <div className="mt-2 font-mono text-[10px] text-on-surface-variant">
                    {drive.file_count} files / {formatBytes(drive.size)}
                  </div>
                </div>
              ))}
            </div>
          </GlassPanel>
        </div>
      </div>
    </div>
  )
}

export default CaseFilesPage
