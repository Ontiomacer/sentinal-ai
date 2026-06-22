import { useState, useEffect, useRef } from 'react'
import { useOutletContext } from 'react-router-dom'
import GlassPanel from '../components/ui/GlassPanel'
import { CaseResponse, Evidence, uploadEvidence, listEvidence, analyzeEvidence, deleteEvidence } from '../services/caseApi'
import { getUploadFailureMessage, shouldResetUploadFile } from '../utils/uploadErrors'

interface CaseContextType {
  caseData: CaseResponse
  refreshCase: () => void
}

const CaseEvidencePage = () => {
  const { caseData, refreshCase } = useOutletContext<CaseContextType>()
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [notes, setNotes] = useState('')
  const [showUploadModal, setShowUploadModal] = useState(false)
  const [showAnalysisModal, setShowAnalysisModal] = useState(false)
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null)
  const [selectedPipeline, setSelectedPipeline] = useState<'neural_ai' | 'deep_reverse_engineering'>('neural_ai')
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    fetchEvidence()
  }, [caseData.id])

  const fetchEvidence = async () => {
    try {
      setLoading(true)
      const data = await listEvidence(caseData.id)
      setEvidence(data)
    } catch (error) {
      console.error('Failed to fetch evidence:', error)
    } finally {
      setLoading(false)
    }
  }

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
      await fetchEvidence()
      await refreshCase()
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

  const handleAnalyze = async () => {
    if (!selectedEvidence) return

    try {
      await analyzeEvidence(caseData.id, selectedEvidence.id, selectedPipeline)
      setShowAnalysisModal(false)
      setSelectedEvidence(null)
      alert('Analysis started successfully')
      await fetchEvidence()
    } catch (error) {
      console.error('Failed to start analysis:', error)
      alert('Failed to start analysis')
    }
  }

  const handleDelete = async (evidenceId: string) => {
    if (!confirm('Are you sure you want to delete this evidence?')) return

    try {
      await deleteEvidence(caseData.id, evidenceId)
      await fetchEvidence()
      await refreshCase()
    } catch (error) {
      console.error('Failed to delete evidence:', error)
      alert('Failed to delete evidence')
    }
  }

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'complete': return 'text-success'
      case 'failed': return 'text-error'
      case 'ingested': return 'text-on-surface-variant'
      case 'indexing':
      case 'static_analysis':
      case 'ghidra_analysis':
      case 'ai_correlation': return 'text-secondary'
      default: return 'text-on-surface-variant'
    }
  }

  const getStatusLabel = (status: string) => {
    const labels: Record<string, string> = {
      'ingested': 'INGESTED',
      'indexing': 'INDEXING',
      'static_analysis': 'STATIC ANALYSIS',
      'ghidra_analysis': 'GHIDRA ANALYSIS',
      'ai_correlation': 'AI CORRELATION',
      'complete': 'REPORT READY',
      'failed': 'FAILED'
    }
    return labels[status] || status.toUpperCase()
  }

  if (loading) {
    return (
      <div className="fade-in">
        <GlassPanel className="p-12 text-center">
          <span className="material-symbols-outlined text-6xl text-secondary mb-4 block animate-pulse">
            inventory_2
          </span>
          <p className="text-body-md text-on-surface-variant">Loading evidence vault...</p>
        </GlassPanel>
      </div>
    )
  }

  return (
    <div className="fade-in">
      {/* Upload Button */}
      <div className="mb-8">
        <button
          onClick={() => {
            setUploadError(null)
            setShowUploadModal(true)
          }}
          className="btn-primary inline-flex px-8 py-3"
        >
          <span className="material-symbols-outlined">upload</span>
          INGEST EVIDENCE
        </button>
      </div>

      {/* Evidence List */}
      {evidence.length === 0 ? (
        <GlassPanel className="p-12 text-center">
          <span className="material-symbols-outlined text-6xl text-secondary mb-6 block">
            inventory_2
          </span>
          <h2 className="font-title-md text-title-md text-on-surface mb-4">
            Evidence Vault Empty
          </h2>
          <p className="text-body-md text-on-surface-variant mb-8 max-w-2xl mx-auto">
            Upload APKs, DEX files, PCAPs, disk images, logs, and related artifacts to begin forensic analysis.
            All evidence is stored securely with chain of custody tracking.
          </p>
        </GlassPanel>
      ) : (
        <div className="space-y-4">
          {evidence.map((item) => (
            <GlassPanel key={item.id} className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-3">
                    <span className="material-symbols-outlined text-2xl text-secondary">
                      {item.evidence_type === 'apk' ? 'android' :
                       item.evidence_type === 'log' ? 'description' :
                       'insert_drive_file'}
                    </span>
                    <div>
                      <h3 className="font-title-sm text-title-sm text-on-surface">
                        {item.original_filename}
                      </h3>
                      <span className="font-label-sm text-label-sm text-on-surface-variant uppercase">
                        {item.evidence_type}
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                    <div>
                      <span className="font-label-sm text-label-sm text-on-surface-variant block mb-1">
                        SIZE
                      </span>
                      <span className="text-body-md text-on-surface">
                        {formatFileSize(item.file_size)}
                      </span>
                    </div>
                    <div>
                      <span className="font-label-sm text-label-sm text-on-surface-variant block mb-1">
                        UPLOADED
                      </span>
                      <span className="text-body-md text-on-surface">
                        {formatDate(item.created_at)}
                      </span>
                    </div>
                    <div>
                      <span className="font-label-sm text-label-sm text-on-surface-variant block mb-1">
                        SHA256
                      </span>
                      <span className="text-body-md text-on-surface font-mono text-xs">
                        {item.sha256.substring(0, 16)}...
                      </span>
                    </div>
                    <div>
                      <span className="font-label-sm text-label-sm text-on-surface-variant block mb-1">
                        STATUS
                      </span>
                      <span className={`font-label-sm text-label-sm ${getStatusColor(item.analysis_status)}`}>
                        {getStatusLabel(item.analysis_status)}
                      </span>
                    </div>
                  </div>

                  {item.notes && (
                    <p className="text-body-md text-on-surface-variant mb-4">
                      {item.notes}
                    </p>
                  )}

                  <div className="flex gap-2">
                    {item.analysis_status === 'ingested' && (
                      <button
                        onClick={() => {
                          setSelectedEvidence(item)
                          setShowAnalysisModal(true)
                        }}
                        className="btn-secondary px-4 py-2 inline-flex items-center gap-2"
                      >
                        <span className="material-symbols-outlined">science</span>
                        ANALYZE
                      </button>
                    )}
                    {item.analysis_status === 'complete' && (
                      <button className="btn-secondary px-4 py-2 inline-flex items-center gap-2">
                        <span className="material-symbols-outlined">visibility</span>
                        VIEW REPORT
                      </button>
                    )}
                    <button
                      onClick={() => handleDelete(item.id)}
                      className="btn-secondary px-4 py-2 inline-flex items-center gap-2 text-error hover:bg-error/10"
                    >
                      <span className="material-symbols-outlined">delete</span>
                      DELETE
                    </button>
                  </div>
                </div>
              </div>
            </GlassPanel>
          ))}
        </div>
      )}

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
                      APK, DEX, SO, JAR, ZIP, PCAP, IMAGES, DISK IMAGES, LOG, TXT, JSON, XML
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

      {/* Analysis Pipeline Selection Modal */}
      {showAnalysisModal && selectedEvidence && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <GlassPanel className="max-w-3xl w-full p-8">
            <h2 className="font-title-lg text-title-lg text-on-surface mb-2">
              Select Analysis Pipeline
            </h2>
            <p className="text-body-md text-on-surface-variant mb-8">
              Choose the forensic analysis approach for {selectedEvidence.original_filename}
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
              {/* Neural AI Pipeline */}
              <button
                onClick={() => setSelectedPipeline('neural_ai')}
                className={`p-6 rounded border-2 transition-all text-left ${
                  selectedPipeline === 'neural_ai'
                    ? 'border-secondary bg-secondary/10'
                    : 'border-white/10 hover:border-secondary/40'
                }`}
              >
                <div className="flex items-center gap-3 mb-4">
                  <span className="material-symbols-outlined text-3xl text-secondary">
                    neurology
                  </span>
                  <h3 className="font-title-md text-title-md text-on-surface">
                    Neural AI Analysis
                  </h3>
                </div>
                <p className="text-body-md text-on-surface-variant mb-4">
                  Fast behavioral analysis with AI threat cognition
                </p>
                <ul className="space-y-2 text-label-sm text-on-surface-variant">
                  <li>• APK heuristics</li>
                  <li>• Risk scoring</li>
                  <li>• Malware behavior detection</li>
                  <li>• AI threat cognition</li>
                </ul>
              </button>

              {/* Deep Reverse Engineering Pipeline */}
              <button
                onClick={() => setSelectedPipeline('deep_reverse_engineering')}
                className={`p-6 rounded border-2 transition-all text-left ${
                  selectedPipeline === 'deep_reverse_engineering'
                    ? 'border-tertiary bg-tertiary/10'
                    : 'border-white/10 hover:border-tertiary/40'
                }`}
              >
                <div className="flex items-center gap-3 mb-4">
                  <span className="material-symbols-outlined text-3xl text-tertiary">
                    memory
                  </span>
                  <h3 className="font-title-md text-title-md text-on-surface">
                    Deep Reverse Engineering
                  </h3>
                </div>
                <p className="text-body-md text-on-surface-variant mb-4">
                  Comprehensive decompilation and code analysis
                </p>
                <ul className="space-y-2 text-label-sm text-on-surface-variant">
                  <li>• Ghidra integration</li>
                  <li>• JADX decompilation</li>
                  <li>• IOC extraction</li>
                  <li>• Call graph analysis</li>
                </ul>
              </button>
            </div>

            <div className="flex items-center justify-between">
              <button
                onClick={() => {
                  setShowAnalysisModal(false)
                  setSelectedEvidence(null)
                }}
                className="btn-secondary px-6 py-3"
              >
                CANCEL
              </button>
              <button
                onClick={handleAnalyze}
                className="btn-primary px-8 py-3 inline-flex items-center gap-2"
              >
                <span className="material-symbols-outlined">science</span>
                INITIATE ANALYSIS
              </button>
            </div>
          </GlassPanel>
        </div>
      )}
    </div>
  )
}

export default CaseEvidencePage
