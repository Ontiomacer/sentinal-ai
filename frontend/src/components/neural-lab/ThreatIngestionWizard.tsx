import React, { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { listCases, listEvidence, uploadEvidence, CaseResponse, Evidence } from '../../services/caseApi'
import { neuralApi } from '../../services/neuralApi'
import GlassPanel from '../ui/GlassPanel'
import ThreatBadge from '../ui/ThreatBadge'

interface ThreatIngestionWizardProps {
  isOpen: boolean
  onClose: () => void
}

type WizardStep = 'case-select' | 'evidence-select' | 'launching'

export const ThreatIngestionWizard: React.FC<ThreatIngestionWizardProps> = ({ isOpen, onClose }) => {
  const navigate = useNavigate()
  const [step, setStep] = useState<WizardStep>('case-select')
  const [cases, setCases] = useState<CaseResponse[]>([])
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null)
  
  const [evidenceList, setEvidenceList] = useState<Evidence[]>([])
  
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)
  
  const [uploading, setUploading] = useState<boolean>(false)
  const [uploadProgress, setUploadProgress] = useState<number>(0)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Fetch active cases on open
  useEffect(() => {
    if (isOpen) {
      setStep('case-select')
      setSelectedCaseId(null)
      setCases([])
      setEvidenceList([])
      setError(null)
      fetchCases()
    }
  }, [isOpen])

  const fetchCases = async () => {
    setLoading(true)
    setError(null)
    try {
      const activeCases = await listCases('active')
      setCases(activeCases)
      
      // Auto-select if there is exactly 1 active case
      if (activeCases.length === 1) {
        const singleCaseId = activeCases[0].id
        setSelectedCaseId(singleCaseId)
        setStep('evidence-select')
        fetchEvidence(singleCaseId)
      }
    } catch (err: any) {
      console.error('Failed to load cases:', err)
      setError('Failed to load active cases. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const fetchEvidence = async (caseId: string) => {
    setLoading(true)
    setError(null)
    try {
      const list = await listEvidence(caseId)
      // Filter for APK or DEX files (case insensitive)
      const filtered = list.filter(item => {
        const ext = item.original_filename.split('.').pop()?.toLowerCase()
        return ext === 'apk' || ext === 'dex'
      })
      setEvidenceList(filtered)
    } catch (err: any) {
      console.error('Failed to load evidence:', err)
      setError('Failed to retrieve case evidence. Please check connections.')
    } finally {
      setLoading(false)
    }
  }

  const handleSelectCase = (caseId: string) => {
    setSelectedCaseId(caseId)
    setStep('evidence-select')
    fetchEvidence(caseId)
  }

  const handleSelectEvidence = (evidenceId: string) => {
    handleLaunch(evidenceId)
  }

  const handleLaunch = async (evidenceId: string) => {
    if (!selectedCaseId) return
    setStep('launching')
    setLoading(true)
    setError(null)
    try {
      // Calls POST /api/v1/neural/bridge-evidence
      const res = await neuralApi.bridgeEvidence(selectedCaseId, evidenceId)
      // Navigate to /neural-lab/:scanId
      navigate(`/neural-lab/${res.scan_id}`)
      onClose()
    } catch (err: any) {
      console.error('Failed to bridge evidence:', err)
      setError('Failed to initiate Neural Lab session. Ensure the file hash is valid.')
      setStep('evidence-select')
    } finally {
      setLoading(false)
    }
  }

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files
    if (!files || files.length === 0 || !selectedCaseId) return
    const file = files[0]
    
    setUploading(true)
    setError(null)
    setUploadProgress(20)
    try {
      // Upload evidence as case evidence
      setUploadProgress(50)
      const uploaded = await uploadEvidence(selectedCaseId, file, 'Uploaded via Neural Lab Ingestion Wizard')
      setUploadProgress(90)
      
      // Re-fetch evidence list to show new file
      await fetchEvidence(selectedCaseId)
      
      // Auto-select the newly uploaded file if it matches apk/dex
      const ext = uploaded.original_filename.split('.').pop()?.toLowerCase()
      if (ext === 'apk' || ext === 'dex') {
        handleSelectEvidence(uploaded.id)
      } else {
        setError('Uploaded file is not an APK or DEX. Please select a valid package.')
      }
    } catch (err: any) {
      console.error('Upload failed:', err)
      setError('Upload failed. Please ensure the APK file is less than 100MB.')
    } finally {
      setUploading(false)
      setUploadProgress(0)
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-background/80 backdrop-blur-md z-50 flex items-center justify-center p-4 animate-fade-in">
      <GlassPanel className="max-w-2xl w-full rounded-2xl shadow-2xl relative overflow-hidden flex flex-col max-h-[85vh] border-glow border-outline-variant/30">
        
        {/* Step Indicator Header */}
        <div className="p-6 border-b border-outline-variant/20 bg-surface-container/20">
          <div className="flex justify-between items-center mb-6">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-secondary animate-pulse">neurology</span>
              <span className="font-display-sm text-title-md text-on-surface uppercase tracking-wider">
                Threat Ingestion Wizard
              </span>
            </div>
            <button 
              onClick={onClose} 
              className="text-on-surface-variant hover:text-on-surface p-1 rounded-full hover:bg-surface-container-high transition-colors"
            >
              <span className="material-symbols-outlined text-lg">close</span>
            </button>
          </div>

          {/* Progress Steps */}
          <div className="flex items-center justify-between px-4">
            <div className="flex items-center gap-3">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-label-md font-mono transition-all ${
                step === 'case-select' 
                  ? 'bg-secondary text-on-secondary shadow-glow' 
                  : 'bg-surface-container-highest text-on-surface-variant'
              }`}>
                1
              </div>
              <span className={`text-label-sm font-label-sm ${
                step === 'case-select' ? 'text-on-surface font-semibold' : 'text-on-surface-variant'
              }`}>Case Select</span>
            </div>

            <div className="flex-1 h-[2px] mx-4 bg-outline-variant/30 relative">
              <div className={`absolute left-0 top-0 h-full bg-secondary transition-all duration-300 ${
                step !== 'case-select' ? 'w-full' : 'w-0'
              }`}></div>
            </div>

            <div className="flex items-center gap-3">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-label-md font-mono transition-all ${
                step === 'evidence-select' 
                  ? 'bg-secondary text-on-secondary shadow-glow' 
                  : step === 'launching'
                    ? 'bg-secondary text-on-secondary shadow-glow'
                    : 'bg-surface-container-highest text-on-surface-variant'
              }`}>
                2
              </div>
              <span className={`text-label-sm font-label-sm ${
                step === 'evidence-select' ? 'text-on-surface font-semibold' : 'text-on-surface-variant'
              }`}>Evidence Selection</span>
            </div>
          </div>
        </div>

        {/* Content Section (Scrollable) */}
        <div className="flex-1 overflow-y-auto p-6 custom-scrollbar min-h-[300px]">
          {error && (
            <div className="mb-6 p-4 rounded bg-error/10 border border-error/20 flex gap-3 text-error text-body-md items-start animate-shake">
              <span className="material-symbols-outlined text-lg mt-0.5">warning</span>
              <div className="flex-1">{error}</div>
              <button onClick={() => setError(null)} className="opacity-70 hover:opacity-100">
                <span className="material-symbols-outlined text-md">close</span>
              </button>
            </div>
          )}

          {loading && step !== 'launching' && (
            <div className="flex flex-col items-center justify-center py-12">
              <div className="relative w-12 h-12 mb-4">
                <div className="absolute inset-0 border-4 border-outline-variant/30 rounded-full"></div>
                <div className="absolute inset-0 border-4 border-t-secondary rounded-full animate-spin"></div>
              </div>
              <p className="text-body-md text-on-surface-variant font-mono">Retrieving remote repositories...</p>
            </div>
          )}

          {/* STEP 1: Case Selection */}
          {!loading && step === 'case-select' && (
            <div className="space-y-4">
              <p className="text-body-md text-on-surface-variant mb-4">
                Select an active case to bind this malware investigation.
              </p>
              {cases.length === 0 ? (
                <div className="p-8 text-center glass-panel rounded-xl">
                  <span className="material-symbols-outlined text-4xl text-on-surface-variant/40 mb-3 block">folder_open</span>
                  <p className="text-body-md text-on-surface-variant mb-6">No active investigation cases exist.</p>
                  <button 
                    onClick={() => { onClose(); navigate('/cases/new') }} 
                    className="btn-primary inline-flex px-6 py-2.5 w-auto"
                  >
                    <span className="material-symbols-outlined text-md">add</span>
                    Create New Case
                  </button>
                </div>
              ) : (
                <div className="space-y-3 max-h-[350px] overflow-y-auto pr-1">
                  {cases.map((c) => (
                    <div 
                      key={c.id} 
                      onClick={() => handleSelectCase(c.id)}
                      className="p-4 rounded-xl border border-outline-variant/30 bg-surface-container/10 hover:bg-surface-container-high/40 hover:border-secondary/40 transition-all cursor-pointer group flex justify-between items-center"
                    >
                      <div className="flex-1 min-w-0 pr-4">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-mono text-label-sm text-secondary uppercase font-semibold">{c.id}</span>
                          <span className="text-on-surface-variant/30">•</span>
                          <span className="text-body-sm text-on-surface-variant">{new Date(c.created_at).toLocaleDateString()}</span>
                        </div>
                        <h4 className="font-title-md text-title-md text-on-surface truncate group-hover:text-secondary transition-colors">
                          {c.name}
                        </h4>
                        {c.description && (
                          <p className="text-body-sm text-on-surface-variant truncate mt-1">{c.description}</p>
                        )}
                      </div>
                      {(() => {
                        const sevUpper = c.severity.toUpperCase()
                        const mappedSev = (sevUpper === 'INFO' ? 'LOW' : (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(sevUpper) ? sevUpper : 'MEDIUM')) as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
                        return <ThreatBadge severity={mappedSev} label={c.severity} />
                      })()}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* STEP 2: Evidence Selection */}
          {!loading && step === 'evidence-select' && (
            <div className="space-y-4">
              <div className="flex justify-between items-center mb-4">
                <div>
                  <h3 className="font-title-md text-title-md text-on-surface">Case Evidence packages</h3>
                  <p className="text-body-sm text-on-surface-variant mt-0.5">Select a JADX/reverse-ready APK or DEX package</p>
                </div>
                <button 
                  onClick={() => fileInputRef.current?.click()} 
                  disabled={uploading}
                  className="btn-secondary flex items-center gap-2 text-label-sm px-4 py-2 hover:bg-secondary/10 hover:border-secondary/30"
                >
                  <span className="material-symbols-outlined text-md">upload</span>
                  {uploading ? 'Uploading...' : 'Upload APK'}
                </button>
                <input 
                  type="file" 
                  ref={fileInputRef} 
                  onChange={handleFileUpload} 
                  className="hidden" 
                  accept=".apk,.dex"
                />
              </div>

              {uploading && (
                <div className="p-4 rounded-xl border border-secondary/20 bg-secondary/5 mb-4 animate-pulse">
                  <div className="flex justify-between text-body-sm font-mono mb-2">
                    <span className="text-secondary">Uploading payload to server...</span>
                    <span>{uploadProgress}%</span>
                  </div>
                  <div className="w-full bg-surface-container-highest h-1.5 rounded-full overflow-hidden">
                    <div 
                      className="bg-secondary h-full transition-all duration-300 shimmer-bar" 
                      style={{ width: `${uploadProgress}%` }}
                    ></div>
                  </div>
                </div>
              )}

              {evidenceList.length === 0 ? (
                <div className="p-12 text-center glass-panel rounded-xl flex flex-col items-center justify-center">
                  <span className="material-symbols-outlined text-5xl text-on-surface-variant/30 mb-4 animate-bounce">upload_file</span>
                  <p className="text-body-md text-on-surface-variant mb-6">No executable package files (.apk / .dex) exist in this case directory yet.</p>
                  <button 
                    onClick={() => fileInputRef.current?.click()} 
                    disabled={uploading}
                    className="btn-primary inline-flex px-8 py-3 w-auto"
                  >
                    <span className="material-symbols-outlined">upload</span>
                    Select and Ingest New APK
                  </button>
                </div>
              ) : (
                <div className="space-y-3 max-h-[300px] overflow-y-auto pr-1">
                  {evidenceList.map((ev) => (
                    <div 
                      key={ev.id} 
                      onClick={() => handleSelectEvidence(ev.id)}
                      className="p-4 rounded-xl border border-outline-variant/30 bg-surface-container/10 hover:bg-surface-container-high/40 hover:border-secondary/40 transition-all cursor-pointer group flex items-start gap-4"
                    >
                      <span className="material-symbols-outlined text-3xl text-secondary mt-1">
                        deployed_code
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="flex justify-between items-start gap-2 mb-1">
                          <h4 className="font-title-md text-title-md text-on-surface truncate group-hover:text-secondary transition-colors">
                            {ev.original_filename}
                          </h4>
                          <span className="font-mono text-body-sm text-on-surface-variant/60 whitespace-nowrap">
                            {(ev.file_size / (1024 * 1024)).toFixed(2)} MB
                          </span>
                        </div>
                        <p className="font-mono text-body-sm text-on-surface-variant/40 truncate">
                          SHA256: {ev.sha256}
                        </p>
                        <div className="flex justify-between items-center mt-3 text-body-sm text-on-surface-variant">
                          <span>Uploaded {new Date(ev.created_at).toLocaleDateString()}</span>
                          {ev.analysis_status === 'completed' && (
                            <span className="text-secondary flex items-center gap-1">
                              <span className="material-symbols-outlined text-sm">verified</span>
                              Analysis Complete
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* STEP 3: Launching Screen */}
          {step === 'launching' && (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <div className="relative w-20 h-20 mb-8">
                <span className="material-symbols-outlined text-6xl text-secondary absolute inset-0 flex items-center justify-center animate-pulse">
                  neurology
                </span>
                <svg className="w-full h-full animate-spin" viewBox="0 0 100 100">
                  <circle 
                    cx="50" 
                    cy="50" 
                    r="40" 
                    stroke="rgba(166, 200, 255, 0.1)" 
                    strokeWidth="4" 
                    fill="none" 
                  />
                  <circle 
                    cx="50" 
                    cy="50" 
                    r="40" 
                    stroke="var(--md-sys-color-secondary, #a6c8ff)" 
                    strokeWidth="4" 
                    fill="none" 
                    strokeDasharray="80 180" 
                  />
                </svg>
              </div>
              <h3 className="font-display-sm text-display-sm text-on-surface mb-3 tracking-wide">
                INITIATING COGNITIVE HANDSHAKE
              </h3>
              <p className="text-body-md text-on-surface-variant max-w-md mx-auto leading-relaxed">
                Bridging forensic case directories with AI cognition nodes. Building decompilation trees and analyzing package namespace signatures...
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-outline-variant/10 flex justify-between items-center bg-surface-container/10">
          <div>
            {step === 'evidence-select' && cases.length > 1 && (
              <button 
                onClick={() => setStep('case-select')} 
                className="btn-secondary text-label-sm flex items-center gap-1.5"
              >
                <span className="material-symbols-outlined text-md">arrow_back</span>
                Change Case
              </button>
            )}
          </div>
          <button 
            onClick={onClose} 
            disabled={step === 'launching'}
            className="text-label-sm text-on-surface-variant hover:text-on-surface px-4 py-2 rounded hover:bg-surface-container-high transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
        </div>
      </GlassPanel>
    </div>
  )
}
