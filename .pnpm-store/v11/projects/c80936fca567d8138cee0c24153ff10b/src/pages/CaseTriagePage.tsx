import { useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import GlassPanel from '../components/ui/GlassPanel'
import {
  CaseResponse,
  CaseTriage,
  TriageDrive,
  TriageFile,
  getCaseTriage,
  importTriageFile
} from '../services/caseApi'

interface CaseContextType {
  caseData: CaseResponse
  refreshCase: () => void
}

const formatBytes = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

const CaseTriagePage = () => {
  const { caseData, refreshCase } = useOutletContext<CaseContextType>()
  const [triage, setTriage] = useState<CaseTriage | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedDrive, setSelectedDrive] = useState<TriageDrive | null>(null)
  const [importingFile, setImportingFile] = useState<string | null>(null)
  const [importSuccess, setImportSuccess] = useState<string | null>(null)

  const fetchTriageData = async () => {
    try {
      setLoading(true)
      const data = await getCaseTriage(caseData.id)
      setTriage(data)
      
      // Auto-select first drive or update selectedDrive reference
      if (data.drives.length > 0) {
        const currentSelected = selectedDrive
          ? data.drives.find(d => d.path === selectedDrive.path)
          : null
        setSelectedDrive(currentSelected || data.drives[0])
      }
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch triage drives')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchTriageData()
    const interval = setInterval(fetchTriageData, 15000)
    return () => clearInterval(interval)
  }, [caseData.id])

  const handleImport = async (file: TriageFile) => {
    try {
      setError(null)
      setImportSuccess(null)
      setImportingFile(file.path)
      await importTriageFile(caseData.id, file.path)
      setImportSuccess(`Successfully imported ${file.name} to Case Evidence Vault.`)
      await refreshCase()
      await fetchTriageData()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to import file')
    } finally {
      setImportingFile(null)
    }
  }

  const getDriveStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'ready': return 'triage-drive-ready hover:shadow-emerald-500/5'
      case 'missing': return 'triage-drive-missing hover:shadow-red-500/5'
      default: return 'border-l-amber-500 hover:shadow-amber-500/5'
    }
  }

  const getDriveStatusBadge = (status: string) => {
    const isReady = status.toLowerCase() === 'ready'
    return (
      <span className={`px-2 py-0.5 rounded font-mono text-[9px] tracking-wider uppercase ${
        isReady ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'
      }`}>
        {status}
      </span>
    )
  }

  if (loading && !triage) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[40vh] gap-3">
        <span className="material-symbols-outlined text-4xl text-secondary animate-spin">
          progress_activity
        </span>
        <span className="font-mono text-xs text-on-surface-variant/60">
          SCANNING FORENSIC TRIAGE DRIVE ROOTS...
        </span>
      </div>
    )
  }

  return (
    <div className="fade-in space-y-6 max-w-7xl">
      {/* Messages */}
      {error && (
        <GlassPanel className="p-4 border-error/30 bg-error/5 animate-shake">
          <div className="flex items-center gap-2 text-error">
            <span className="material-symbols-outlined">error</span>
            <span className="font-mono text-label-sm">{error}</span>
          </div>
        </GlassPanel>
      )}

      {importSuccess && (
        <GlassPanel className="p-4 border-emerald-500/30 bg-emerald-500/5">
          <div className="flex items-center gap-2 text-emerald-400">
            <span className="material-symbols-outlined">check_circle</span>
            <span className="font-mono text-label-sm">{importSuccess}</span>
          </div>
        </GlassPanel>
      )}

      {/* Overview stats & Info */}
      <GlassPanel className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="font-title-md text-title-md text-on-surface uppercase tracking-wide mb-1">
            Forensic Triage Acquisition
          </h2>
          <p className="text-body-sm text-on-surface-variant/70 max-w-xl">
            Triage drives represent read-only forensic disk images, physical partitions, or intake folders. Use this console to review drive inventories and import suspects directly into the investigation vault.
          </p>
        </div>
        <div className="font-mono text-xs text-on-surface-variant/50 border-t md:border-t-0 md:border-l border-white/10 pt-3 md:pt-0 md:pl-4">
          <div>ENV SOURCE: <span className="text-on-surface">{triage?.configured_roots_env}</span></div>
          <div className="mt-1">ACTIVE MOUNT PATHS: <span className="text-on-surface">{triage?.drives.length}</span></div>
        </div>
      </GlassPanel>

      {/* Grid: Left - Drives, Right - Files inside selected drive */}
      <div className="grid grid-cols-1 lg:grid-cols-[380px_1fr] gap-6">
        
        {/* Left Column: Drives */}
        <div className="space-y-4">
          <h3 className="font-mono text-[10px] tracking-widest text-on-surface-variant/60 uppercase">
            DETECTED DRIVES ({triage?.drives.length})
          </h3>
          
          <div className="space-y-3">
            {triage?.drives.map((drive) => (
              <button
                key={drive.path}
                onClick={() => setSelectedDrive(drive)}
                className={`w-full text-left triage-drive-card group ${getDriveStatusColor(drive.status)} ${
                  selectedDrive?.path === drive.path ? 'bg-white/[0.03] border-secondary' : ''
                }`}
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="min-w-0 flex-1">
                    <h4 className="font-title-sm text-title-sm text-on-surface truncate group-hover:text-secondary transition-colors">
                      {drive.name}
                    </h4>
                    <span className="font-mono text-[9px] text-on-surface-variant/50 truncate block mt-0.5">
                      {drive.path}
                    </span>
                  </div>
                  {getDriveStatusBadge(drive.status)}
                </div>

                <div className="grid grid-cols-2 gap-2 mt-3 pt-3 border-t border-white/5 font-mono text-[10px] text-on-surface-variant/50">
                  <div>FILES: <span className="text-on-surface">{drive.file_count}</span></div>
                  <div>SIZE: <span className="text-on-surface">{formatBytes(drive.size)}</span></div>
                </div>

                {drive.is_case_triage && (
                  <div className="mt-2 text-[9px] font-mono text-secondary uppercase tracking-widest flex items-center gap-1.5">
                    <span className="inline-block w-1 h-1 rounded-full bg-secondary" />
                    Case Custom Triage Directory
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Right Column: Files */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="font-mono text-[10px] tracking-widest text-on-surface-variant/60 uppercase">
              DRIVE FILE INVENTORY
            </h3>
            {selectedDrive && (
              <span className="font-mono text-[10px] text-on-surface-variant/40">
                PATH: {selectedDrive.path}
              </span>
            )}
          </div>

          <GlassPanel className="overflow-hidden min-h-[400px] flex flex-col">
            {selectedDrive && selectedDrive.status.toLowerCase() === 'ready' ? (
              selectedDrive.files.length === 0 ? (
                <div className="flex-1 flex flex-col items-center justify-center p-12 text-center my-auto">
                  <span className="material-symbols-outlined text-5xl text-on-surface-variant/20 mb-3">
                    folder_open
                  </span>
                  <h4 className="font-title-sm text-title-sm text-on-surface/85 mb-1">
                    Drive is Empty
                  </h4>
                  <p className="text-body-sm text-on-surface-variant/50 max-w-sm">
                    No files discovered inside this triage partition. Put files inside the custom case triage folder to see them here.
                  </p>
                </div>
              ) : (
                <div className="flex-1 overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs divide-y divide-white/5">
                    <thead>
                      <tr className="bg-black/25 text-on-surface-variant/60 font-semibold border-b border-white/10 uppercase tracking-wider h-10">
                        <th className="pl-4 py-2">Filename</th>
                        <th className="py-2">Path</th>
                        <th className="py-2 text-right">Size</th>
                        <th className="py-2 text-center">Modified At</th>
                        <th className="pr-4 py-2 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 bg-black/10">
                      {selectedDrive.files.map((file) => (
                        <tr key={file.path} className="hover:bg-white/[0.02] transition-colors h-12">
                          <td className="pl-4 font-semibold text-on-surface truncate max-w-[180px]" title={file.name}>
                            {file.name}
                          </td>
                          <td className="text-on-surface-variant/50 truncate max-w-[200px]" title={file.path}>
                            {file.path}
                          </td>
                          <td className="text-right text-on-surface-variant/80">
                            {formatBytes(file.size)}
                          </td>
                          <td className="text-center text-on-surface-variant/55">
                            {new Date(file.modified_at).toLocaleString()}
                          </td>
                          <td className="pr-4 text-right">
                            <button
                              onClick={() => handleImport(file)}
                              disabled={importingFile !== null}
                              className="px-3 py-1 bg-secondary text-on-secondary hover:opacity-90 font-label-sm text-[10px] rounded transition-all inline-flex items-center gap-1 disabled:opacity-50"
                            >
                              <span className="material-symbols-outlined text-sm">
                                {importingFile === file.path ? 'progress_activity' : 'arrow_downward'}
                              </span>
                              {importingFile === file.path ? 'IMPORTING...' : 'IMPORT'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center p-12 text-center my-auto">
                <span className="material-symbols-outlined text-5xl text-red-400/30 mb-3 animate-pulse">
                  device_unknown
                </span>
                <h4 className="font-title-sm text-title-sm text-on-surface/85 mb-1 uppercase text-red-400">
                  Drive Offline or Missing
                </h4>
                <p className="text-body-sm text-on-surface-variant/50 max-w-sm">
                  The selected forensic partition is currently missing or disconnected. Please mount the triage drive to access its files.
                </p>
              </div>
            )}
          </GlassPanel>
        </div>
      </div>
    </div>
  )
}

export default CaseTriagePage
