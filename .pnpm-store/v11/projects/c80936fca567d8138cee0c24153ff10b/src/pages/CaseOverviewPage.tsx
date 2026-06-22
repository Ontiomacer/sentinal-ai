import { useEffect, useRef, useState } from 'react'
import { useOutletContext, useNavigate } from 'react-router-dom'
import AISuggestionsPanel from '../components/AISuggestionsPanel'
import GlassPanel from '../components/ui/GlassPanel'
import { CaseResponse, TimelineEvent, listTimelineEvents, uploadEvidence } from '../services/caseApi'
import { getUploadFailureMessage, shouldResetUploadFile } from '../utils/uploadErrors'

interface CaseContextType {
  caseData: CaseResponse
  refreshCase: () => void
}

const CaseOverviewPage = () => {
  const { caseData, refreshCase } = useOutletContext<CaseContextType>()
  const navigate = useNavigate()
  const [showUploadModal, setShowUploadModal] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [notes, setNotes] = useState('')
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [recentEvents, setRecentEvents] = useState<TimelineEvent[]>([])
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    listTimelineEvents(caseData.id)
      .then(events => setRecentEvents(events.slice(0, 6)))
      .catch(() => setRecentEvents([]))
  }, [caseData.id, caseData.timeline_count])

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] ?? null
    setSelectedFile(file)
    setUploadError(null)
  }

  const resetUploadForm = () => {
    setSelectedFile(null)
    setNotes('')
    setUploadError(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const handleUpload = async () => {
    if (!selectedFile) return

    try {
      setUploading(true)
      setUploadError(null)
      await uploadEvidence(caseData.id, selectedFile, notes)
      setShowUploadModal(false)
      resetUploadForm()
      await refreshCase()
      const events = await listTimelineEvents(caseData.id)
      setRecentEvents(events.slice(0, 6))
      // Navigate to evidence tab
      navigate(`/cases/${caseData.id}/evidence`)
    } catch (error) {
      console.error('Failed to upload evidence:', error)
      setUploadError(getUploadFailureMessage(error))
      if (shouldResetUploadFile(error)) {
        setSelectedFile(null)
        if (fileInputRef.current) {
          fileInputRef.current.value = ''
        }
      }
    } finally {
      setUploading(false)
    }
  }

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  return (
    <div className="fade-in">
      {/* Statistics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-gutter mb-8">
        <GlassPanel className="p-6">
          <div className="flex items-center justify-between mb-4">
            <span className="material-symbols-outlined text-3xl text-secondary">
              inventory_2
            </span>
            <span className="font-display-xl text-title-md text-secondary">
              {caseData.evidence_count}
            </span>
          </div>
          <h3 className="font-title-md text-title-md mb-2 text-on-surface">
            Evidence Items
          </h3>
          <p className="text-body-md text-on-surface-variant">
            Uploaded artifacts and files
          </p>
        </GlassPanel>

        <GlassPanel className="p-6">
          <div className="flex items-center justify-between mb-4">
            <span className="material-symbols-outlined text-3xl text-tertiary">
              hub
            </span>
            <span className="font-display-xl text-title-md text-tertiary">
              {caseData.entity_count}
            </span>
          </div>
          <h3 className="font-title-md text-title-md mb-2 text-on-surface">
            Tracked Entities
          </h3>
          <p className="text-body-md text-on-surface-variant">
            IOCs, actors, infrastructure
          </p>
        </GlassPanel>

        <GlassPanel className="p-6">
          <div className="flex items-center justify-between mb-4">
            <span className="material-symbols-outlined text-3xl text-primary">
              timeline
            </span>
            <span className="font-display-xl text-title-md text-primary">
              {caseData.timeline_count}
            </span>
          </div>
          <h3 className="font-title-md text-title-md mb-2 text-on-surface">
            Timeline Events
          </h3>
          <p className="text-body-md text-on-surface-variant">
            Investigation milestones
          </p>
        </GlassPanel>

        <GlassPanel className="p-6">
          <div className="flex items-center justify-between mb-4">
            <span className="material-symbols-outlined text-3xl text-on-surface">
              description
            </span>
            <span className="font-display-xl text-title-md text-on-surface">
              {caseData.note_count}
            </span>
          </div>
          <h3 className="font-title-md text-title-md mb-2 text-on-surface">
            Investigator Notes
          </h3>
          <p className="text-body-md text-on-surface-variant">
            Findings and observations
          </p>
        </GlassPanel>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-gutter mb-8">
        <GlassPanel className="p-8 hover:border-secondary/60 transition-all">
          <div className="flex items-start gap-4">
            <span className="material-symbols-outlined text-4xl text-secondary">
              upload
            </span>
            <div className="flex-1">
              <h3 className="font-title-md text-title-md text-on-surface mb-2">
                Upload Evidence
              </h3>
              <p className="text-body-md text-on-surface-variant mb-4">
                Add APKs, documents, logs, or other artifacts to the evidence vault
              </p>
              <button 
                onClick={() => {
                  setUploadError(null)
                  setShowUploadModal(true)
                }}
                className="btn-secondary px-4 py-2 inline-flex items-center gap-2"
              >
                <span className="material-symbols-outlined">add</span>
                ADD EVIDENCE
              </button>
            </div>
          </div>
        </GlassPanel>

        <GlassPanel className="p-8 hover:border-tertiary/60 transition-all">
          <div className="flex items-start gap-4">
            <span className="material-symbols-outlined text-4xl text-tertiary">
              neurology
            </span>
            <div className="flex-1">
              <h3 className="font-title-md text-title-md text-on-surface mb-2">
                Neural Lab Analysis
              </h3>
              <p className="text-body-md text-on-surface-variant mb-4">
                AI-powered reverse engineering and malware cognition
              </p>
              <button 
                onClick={() => navigate(`/cases/${caseData.id}/neural-lab`)}
                className="btn-secondary px-4 py-2 inline-flex items-center gap-2"
              >
                <span className="material-symbols-outlined">science</span>
                OPEN LAB
              </button>
            </div>
          </div>
        </GlassPanel>

        <GlassPanel className="p-8 hover:border-primary/60 transition-all">
          <div className="flex items-start gap-4">
            <span className="material-symbols-outlined text-4xl text-primary">
              folder_managed
            </span>
            <div className="flex-1">
              <h3 className="font-title-md text-title-md text-on-surface mb-2">
                Case Filesystem
              </h3>
              <p className="text-body-md text-on-surface-variant mb-4">
                Browse Evidence, Extracted, Reports, Timeline, Memory, Network, and triage intake
              </p>
              <button 
                onClick={() => navigate(`/cases/${caseData.id}/files`)}
                className="btn-secondary px-4 py-2 inline-flex items-center gap-2"
              >
                <span className="material-symbols-outlined">account_tree</span>
                OPEN FILES
              </button>
            </div>
          </div>
        </GlassPanel>
      </div>

      <div className="mb-8">
        <AISuggestionsPanel
          caseId={caseData.id}
          context={{
            severity: caseData.severity,
            status: caseData.status,
            case_name: caseData.name,
          }}
        />
      </div>

      {/* Recent Activity */}
      <GlassPanel className="p-8">
        <h3 className="font-title-md text-title-md text-on-surface mb-6">
          Recent Activity
        </h3>
        {recentEvents.length === 0 ? (
          <div className="text-center py-12">
            <span className="material-symbols-outlined text-6xl text-on-surface-variant mb-4 block opacity-30">
              history
            </span>
            <p className="text-body-md text-on-surface-variant">
              No activity yet. Start by uploading evidence or creating timeline events.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {recentEvents.map(event => (
              <div key={event.id} className="border border-white/5 bg-black/20 px-4 py-3 flex items-start gap-3">
                <span className="material-symbols-outlined text-secondary text-[18px] mt-0.5">
                  {event.event_type === 'upload' ? 'upload_file' : event.event_type === 'report' ? 'article' : 'history'}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-4">
                    <p className="font-mono text-[12px] text-on-surface truncate">{event.title}</p>
                    <span className="font-mono text-[10px] text-on-surface-variant shrink-0">
                      {new Date(event.created_at).toLocaleString()}
                    </span>
                  </div>
                  {event.description && (
                    <p className="text-[12px] text-on-surface-variant mt-1">{event.description}</p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </GlassPanel>

      {/* Upload Modal */}
      {showUploadModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <GlassPanel className="max-w-2xl w-full p-8">
            <h2 className="font-title-lg text-title-lg text-on-surface mb-6">
              Ingest Evidence
            </h2>

            <div className="mb-6">
              <input
                ref={fileInputRef}
                type="file"
                onChange={handleFileSelect}
                accept=".apk,.dex,.so,.jar,.zip,.pcap,.pcapng,.png,.jpg,.jpeg,.webp,.gif,.img,.dd,.raw,.log,.txt,.json,.xml"
                className="hidden"
                disabled={uploading}
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
                className="w-full p-8 border-2 border-dashed border-white/20 rounded hover:border-secondary/60 transition-all"
              >
                {selectedFile ? (
                  <div>
                    <span className="material-symbols-outlined text-4xl text-secondary mb-2 block">
                      check_circle
                    </span>
                    <p className="text-body-md text-on-surface">{selectedFile.name}</p>
                    <p className="text-label-sm text-on-surface-variant">
                      {formatFileSize(selectedFile.size)}
                    </p>
                  </div>
                ) : (
                  <div>
                    <span className="material-symbols-outlined text-4xl text-on-surface-variant mb-2 block">
                      upload_file
                    </span>
                    <p className="text-body-md text-on-surface">Click to select file</p>
                    <p className="text-label-sm text-on-surface-variant">
                      APK, ZIP, DEX, PCAP, images, disk images, logs, JSON, XML
                    </p>
                  </div>
                )}
              </button>
            </div>

            {uploadError && (
              <div
                role="alert"
                className="mb-6 p-4 bg-error/10 border border-error/20 rounded flex gap-3 text-error text-body-md items-start"
              >
                <span className="material-symbols-outlined text-error">error</span>
                <span>{uploadError}</span>
              </div>
            )}

            <div className="mb-6">
              <label className="block font-label-sm text-label-sm text-on-surface-variant uppercase mb-2">
                Chain of Custody Notes
              </label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={3}
                placeholder="Optional notes about evidence source, acquisition method, etc..."
                className="w-full px-4 py-3 bg-surface-container border border-white/10 rounded font-body-md text-on-surface placeholder-on-surface-variant/50 focus:outline-none focus:border-secondary transition-colors resize-none"
              />
            </div>

            <div className="flex items-center justify-between">
              <button
                onClick={() => {
                  setShowUploadModal(false)
                  resetUploadForm()
                }}
                className="btn-secondary px-6 py-3"
                disabled={uploading}
              >
                CANCEL
              </button>
              <button
                onClick={handleUpload}
                disabled={!selectedFile || uploading}
                className="btn-primary px-8 py-3 inline-flex items-center gap-2"
              >
                {uploading ? (
                  <>
                    <span className="material-symbols-outlined animate-spin">progress_activity</span>
                    INGESTING...
                  </>
                ) : (
                  <>
                    <span className="material-symbols-outlined">upload</span>
                    INGEST EVIDENCE
                  </>
                )}
              </button>
            </div>
          </GlassPanel>
        </div>
      )}
    </div>
  )
}

export default CaseOverviewPage
