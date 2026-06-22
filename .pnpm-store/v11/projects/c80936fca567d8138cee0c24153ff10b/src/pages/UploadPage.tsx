import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { uploadAPK } from '../services/api'
import GlassPanel from '../components/ui/GlassPanel'
import ThreatBadge from '../components/ui/ThreatBadge'

type CognitionState = 
  | 'Behavioral Correlation Active'
  | 'Entropy Mapping Running'
  | 'Signal Reconstruction Initialized'
  | 'Threat Graph Evolving'
  | 'Neural Synchronization Complete'
  | 'Pattern Recognition Standby'

const UploadPage = () => {
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [ingestionPhase, setIngestionPhase] = useState<string>('')
  const [error, setError] = useState<string | null>(null)
  const [dragActive, setDragActive] = useState(false)
  const [cognitionState, setCognitionState] = useState<CognitionState>('Pattern Recognition Standby')
  const [ambientLogs, setAmbientLogs] = useState<string[]>([])
  const fileInputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()

  // Ambient intelligence background activity
  useEffect(() => {
    const cognitionStates: CognitionState[] = [
      'Pattern Recognition Standby',
      'Behavioral Correlation Active',
      'Entropy Mapping Running',
      'Signal Reconstruction Initialized',
      'Threat Graph Evolving',
      'Neural Synchronization Complete'
    ]

    const ambientMessages = [
      'Telemetry sync: 127 threat signatures updated',
      'Neural model checkpoint: v4.2.1 loaded',
      'Heuristic engine: calibration nominal',
      'Threat intelligence feed: synchronized',
      'Behavioral database: 2.4M patterns indexed',
      'Signal correlation matrix: optimized'
    ]

    // Rotate cognition states subtly
    const stateInterval = setInterval(() => {
      if (!uploading) {
        setCognitionState(prev => {
          const currentIndex = cognitionStates.indexOf(prev)
          return cognitionStates[(currentIndex + 1) % cognitionStates.length]
        })
      }
    }, 8000)

    // Add ambient log messages
    const logInterval = setInterval(() => {
      if (!uploading) {
        setAmbientLogs(prev => {
          const newLog = ambientMessages[Math.floor(Math.random() * ambientMessages.length)]
          return [...prev.slice(-4), newLog]
        })
      }
    }, 12000)

    // Initialize with first log
    setAmbientLogs([ambientMessages[0]])

    return () => {
      clearInterval(stateInterval)
      clearInterval(logInterval)
    }
  }, [uploading])

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const droppedFile = e.dataTransfer.files[0]
      if (droppedFile.name.endsWith('.apk')) {
        setFile(droppedFile)
        setError(null)
      } else {
        setError('Please upload a valid APK file')
      }
    }
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0]
      if (selectedFile.name.endsWith('.apk')) {
        setFile(selectedFile)
        setError(null)
      } else {
        setError('Please upload a valid APK file')
      }
    }
  }

  const handleUpload = async () => {
    if (!file) return

    setUploading(true)
    setError(null)

    // Ingestion phases
    const phases = [
      'Artifact accepted into cognitive pipeline',
      'Initializing behavioral correlation',
      'Mapping entropy signatures',
      'Reconstructing signal patterns',
      'Evolving threat graph',
      'Finalizing neural analysis'
    ]

    let phaseIndex = 0
    const phaseInterval = setInterval(() => {
      if (phaseIndex < phases.length) {
        setIngestionPhase(phases[phaseIndex])
        phaseIndex++
      }
    }, 800)

    try {
      const response = await uploadAPK(file)
      clearInterval(phaseInterval)
      setIngestionPhase('Investigation transition initiated')
      
      // Brief pause before transition to analysis
      setTimeout(() => {
        navigate(`/scan/${response.scan_id}`)
      }, 1200)
    } catch (err: any) {
      clearInterval(phaseInterval)
      setError(err.response?.data?.detail || 'Ingestion failed. Artifact rejected.')
      setUploading(false)
      setIngestionPhase('')
    }
  }

  return (
    <div className="container-padding fade-in">
      {/* Hero Section */}
      <section className="mb-24 relative max-w-4xl">
        <div className="flex items-center gap-2 mb-4">
          <ThreatBadge severity="MEDIUM" label="Neural Analysis Ready" />
          <span className="text-on-surface-variant font-label-sm text-label-sm opacity-50">
            — SYSTEM STATUS: OPERATIONAL
          </span>
        </div>
        <h1 className="font-display-xl text-display-xl tracking-tighter text-on-surface leading-tight mb-6">
          THREAT INGESTION
        </h1>
        <p className="font-body-lg text-body-lg text-on-surface-variant max-w-2xl leading-relaxed">
          Submit APK artifacts for cognitive dissection. The neural analysis engine employs
          multi-layered behavioral correlation to detect obfuscated threats, anomalous patterns,
          and hostile intent invisible to conventional scanners.
        </p>
      </section>

      {/* Ambient Intelligence Layer */}
      <section className="mb-12 max-w-4xl">
        <GlassPanel className="p-4 bg-surface-container/20">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 rounded-full bg-tertiary animate-pulse"></div>
              <span className="font-label-sm text-label-sm text-on-surface-variant">
                [ {cognitionState} ]
              </span>
            </div>
            <div className="font-label-sm text-label-sm text-on-surface-variant/50 font-mono">
              {ambientLogs[ambientLogs.length - 1]}
            </div>
          </div>
        </GlassPanel>
      </section>

      {/* Upload Area */}
      <section className="mb-section-gap max-w-4xl">
        <GlassPanel className="p-12">
          <div
            className={`border-2 border-dashed rounded-xl p-16 text-center transition-all duration-300 ${
              dragActive
                ? 'border-secondary bg-secondary/5'
                : 'border-outline-variant hover:border-secondary/50'
            }`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".apk"
              onChange={handleFileChange}
              className="hidden"
            />

            <div className="flex flex-col items-center gap-6">
              {uploading ? (
                <>
                  <div className="relative">
                    <span className="material-symbols-outlined text-6xl text-secondary">
                      neurology
                    </span>
                    <div className="absolute inset-0 border-2 border-secondary/30 rounded-full animate-ping"></div>
                  </div>
                  <div className="text-center">
                    <p className="font-title-md text-title-md text-on-surface mb-2">
                      Ingesting Threat Artifact
                    </p>
                    <p className="font-label-sm text-label-sm text-on-surface-variant font-mono">
                      {ingestionPhase}
                    </p>
                  </div>
                  <div className="w-64 h-1 bg-surface-container-low rounded-full overflow-hidden">
                    <div className="h-full bg-secondary animate-pulse" style={{ width: '100%' }}></div>
                  </div>
                </>
              ) : (
                <>
                  <span className="material-symbols-outlined text-6xl text-primary">
                    upload_file
                  </span>

                  {!file ? (
                    <>
                      <div>
                        <p className="font-title-md text-title-md text-on-surface mb-2">
                          Drop APK artifact here
                        </p>
                        <p className="font-body-md text-on-surface-variant">
                          or select from local storage
                        </p>
                      </div>
                      <button
                        onClick={() => fileInputRef.current?.click()}
                        className="btn-secondary px-8 py-3 font-label-sm text-label-sm"
                      >
                        SELECT ARTIFACT
                      </button>
                    </>
                  ) : (
                    <>
                      <div className="flex items-center gap-4 glass-panel px-6 py-4 rounded-lg">
                        <span className="material-symbols-outlined text-tertiary">
                          check_circle
                        </span>
                        <div className="text-left">
                          <p className="font-body-md text-on-surface font-medium">{file.name}</p>
                          <p className="font-label-sm text-label-sm text-on-surface-variant">
                            {(file.size / 1024 / 1024).toFixed(2)} MB — Artifact ready for ingestion
                          </p>
                        </div>
                      </div>
                      <div className="flex gap-4">
                        <button
                          onClick={() => setFile(null)}
                          className="btn-secondary px-6 py-2 font-label-sm text-label-sm"
                        >
                          DISCARD
                        </button>
                        <button
                          onClick={handleUpload}
                          disabled={uploading}
                          className="btn-primary px-8 py-3 font-label-sm text-label-sm disabled:opacity-50"
                        >
                          <span className="material-symbols-outlined">neurology</span>
                          INITIATE THREAT INGESTION
                        </button>
                      </div>
                    </>
                  )}
                </>
              )}
            </div>
          </div>

          {error && (
            <div className="mt-6 p-4 glass-panel border-error/50 rounded-lg">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-error">error</span>
                <p className="text-error font-body-md">{error}</p>
              </div>
            </div>
          )}
        </GlassPanel>

        {/* Cognitive Capabilities Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-gutter mt-12">
          <GlassPanel className="p-6">
            <span className="material-symbols-outlined text-3xl text-secondary mb-4 block">
              psychology
            </span>
            <h3 className="font-title-md text-title-md mb-2 text-on-surface">
              Behavioral Correlation
            </h3>
            <p className="text-body-md text-on-surface-variant">
              AI-powered pattern recognition across threat behavioral signatures
            </p>
          </GlassPanel>

          <GlassPanel className="p-6">
            <span className="material-symbols-outlined text-3xl text-tertiary mb-4 block">
              shield
            </span>
            <h3 className="font-title-md text-title-md mb-2 text-on-surface">
              Entropy Mapping
            </h3>
            <p className="text-body-md text-on-surface-variant">
              Signal reconstruction and anomaly detection in obfuscated code
            </p>
          </GlassPanel>

          <GlassPanel className="p-6">
            <span className="material-symbols-outlined text-3xl text-primary mb-4 block">
              hub
            </span>
            <h3 className="font-title-md text-title-md mb-2 text-on-surface">
              Threat Graph Evolution
            </h3>
            <p className="text-body-md text-on-surface-variant">
              Real-time cognitive mapping of attack vectors and intent
            </p>
          </GlassPanel>
        </div>
      </section>
    </div>
  )
}

export default UploadPage
