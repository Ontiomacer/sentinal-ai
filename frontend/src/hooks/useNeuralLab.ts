import { useState, useEffect, useCallback, useRef } from 'react'
import {
  neuralApi,
  Investigation,
  InvestigationNote,
  InvestigationBookmark,
  RiskAssessmentResponse,
  SandboxResponse,
} from '../services/neuralApi'
import { getScan, ScanResponse } from '../services/api'

export interface ChatMessage {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: string
  isStreaming?: boolean
}

export interface PipelineStage {
  id: string
  name: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped'
  label: string
}

export const INITIAL_STAGES: PipelineStage[] = [
  { id: 'yara_scan', name: 'Signature Scan', status: 'pending', label: 'Static signature scanning' },
  { id: 'jadx_decompilation', name: 'Source Recon', status: 'pending', label: 'Java source reconstruction' },
  { id: 'apktool_disassembly', name: 'Artifact Extraction', status: 'pending', label: 'Extracting manifest and assets' },
  { id: 'androguard_analysis', name: 'X-Ref Discovery', status: 'pending', label: 'Method cross-reference discovery' },
  { id: 'string_extraction', name: 'Indicator Extraction', status: 'pending', label: 'Extracting network and file indicators' },
  { id: 'api_correlation', name: 'Capability Analysis', status: 'pending', label: 'Mapping permissions to sensitive APIs' },
  { id: 'obfuscation_detection', name: 'Entropic Analysis', status: 'pending', label: 'Checking identifier renaming and packing' },
  { id: 'reflection_analysis', name: 'Dynamic Reference', status: 'pending', label: 'Checking for dynamic loading and reflection' },
  { id: 'native_analysis', name: 'Native Artifacts', status: 'pending', label: 'Checking ELF structures and JNI exports' },
  { id: 'call_graph', name: 'Relationship Map', status: 'pending', label: 'Compiling function call relationships' },
  { id: 'threat_mapping', name: 'Predicted Matrix', status: 'pending', label: 'Mapping behavior to MITRE matrices' },
  { id: 'ai_cognition', name: 'Fraud Intelligence', status: 'pending', label: 'Specialized banking fraud intelligence mapping' },
]

export const useNeuralLab = (scanId: string) => {
  const [scan, setScan] = useState<ScanResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  
  // Pipeline state
  const [pipelineRunning, setPipelineRunning] = useState(false)
  const [pipelineStages, setPipelineStages] = useState<PipelineStage[]>(INITIAL_STAGES)
  const [pipelineProgress, setPipelineProgress] = useState(0)

  // Risk & Cognition State
  const [riskData, setRiskData] = useState<RiskAssessmentResponse | null>(null)
  const [aiSummary, setAiSummary] = useState<string>('')
  const [sandboxData, setSandboxData] = useState<SandboxResponse | null>(null)
  const [healthStatus, setHealthStatus] = useState<{ healthy: boolean; ollama_running: boolean } | null>(null)

  // Investigation sessions
  const [investigations, setInvestigations] = useState<Investigation[]>([])
  const [activeInvestigation, setActiveInvestigation] = useState<Investigation | null>(null)
  const [notes, setNotes] = useState<InvestigationNote[]>([])
  const [bookmarks, setBookmarks] = useState<InvestigationBookmark[]>([])
  
  // Chat state
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([])
  const [chatLoading, setChatLoading] = useState(false)
  const chatAbortRef = useRef<(() => void) | null>(null)

  // Load basic scan information and health status
  const loadScanData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const scanInfo = await getScan(scanId)
      setScan(scanInfo)

      // Fetch health of Ollama
      try {
        const health = await neuralApi.getHealth()
        setHealthStatus(health)
      } catch (e) {
        setHealthStatus({ healthy: false, ollama_running: false })
      }

      // If neural analysis is already present, load it
      if (scanInfo.analysis_result?.neural_analysis) {
        const neural = scanInfo.analysis_result.neural_analysis
        
        // Update stages
        const completedStages = neural.statistics?.stages_completed || []
        setPipelineStages(prev =>
          prev.map(stage => ({
            ...stage,
            status: completedStages.includes(stage.id) ? 'completed' : 'skipped',
          }))
        )
        setPipelineProgress(100)

        // Load risk & summary
        loadRiskAndSummary()
        loadSandboxData()
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load scan details')
    } finally {
      setLoading(false)
    }
  }, [scanId])

  // Fetch AI threat summaries and risk details
  const loadRiskAndSummary = useCallback(async () => {
    try {
      const risk = await neuralApi.getRisk(scanId)
      setRiskData(risk)
    } catch (e) {
      console.error('Failed to load risk score', e)
    }

    try {
      const summaryRes = await neuralApi.getSummary(scanId)
      setAiSummary(summaryRes.summary)
    } catch (e) {
      console.error('Failed to load summary', e)
    }
  }, [scanId])

  // Fetch static runtime reconstruction data
  const loadSandboxData = useCallback(async () => {
    try {
      const sandbox = await neuralApi.getSandboxTimeline(scanId)
      setSandboxData(sandbox)
    } catch (e) {
      console.error('Failed to load static runtime reconstruction data', e)
    }
  }, [scanId])

  // Fetch investigations sessions list
  const loadInvestigations = useCallback(async () => {
    try {
      const list = await neuralApi.listInvestigations(scanId)
      setInvestigations(list)
      if (list.length > 0 && !activeInvestigation) {
        // Auto-select first active investigation
        switchInvestigation(list[0])
      }
    } catch (e) {
      console.error('Failed to load investigations', e)
    }
  }, [scanId, activeInvestigation])

  // Switch active investigation session
  const switchInvestigation = async (inv: Investigation) => {
    setActiveInvestigation(inv)
    try {
      const noteList = await neuralApi.listNotes(inv.id)
      setNotes(noteList)
      
      const bookmarkList = await neuralApi.listBookmarks(inv.id)
      setBookmarks(bookmarkList)
    } catch (e) {
      console.error('Failed to load investigation contents', e)
    }
  }

  // Create new investigation session
  const createInvestigation = async (title: string, description: string, analystName: string) => {
    try {
      const newInv = await neuralApi.createInvestigation(scanId, title, description, analystName)
      setInvestigations(prev => [newInv, ...prev])
      switchInvestigation(newInv)
      return newInv
    } catch (e) {
      console.error('Failed to create investigation session', e)
      throw e
    }
  }

  // Update investigation status / details
  const updateActiveInvestigation = async (payload: Partial<Investigation>) => {
    if (!activeInvestigation) return
    try {
      const updated = await neuralApi.updateInvestigation(activeInvestigation.id, payload)
      setInvestigations(prev => prev.map(inv => inv.id === updated.id ? updated : inv))
      setActiveInvestigation(updated)
    } catch (e) {
      console.error('Failed to update investigation', e)
    }
  }

  // Add analyst note
  const addNote = async (content: string, noteType: string = 'general', tags: string[] = []) => {
    if (!activeInvestigation) return
    try {
      const newNote = await neuralApi.addNote(activeInvestigation.id, content, noteType, tags)
      setNotes(prev => [newNote, ...prev])
      // Increment notes count locally
      setActiveInvestigation(prev => prev ? { ...prev, notes_count: prev.notes_count + 1 } : null)
    } catch (e) {
      console.error('Failed to add note', e)
    }
  }

  // Bookmark a target item (function, IOC)
  const addBookmark = async (targetType: string, targetId: string, label: string, notesText: string, severity: string) => {
    if (!activeInvestigation) return
    try {
      const newBookmark = await neuralApi.addBookmark(
        activeInvestigation.id,
        targetType,
        targetId,
        label,
        notesText,
        severity
      )
      setBookmarks(prev => [newBookmark, ...prev])
      setActiveInvestigation(prev => prev ? { ...prev, bookmarks_count: prev.bookmarks_count + 1 } : null)
    } catch (e) {
      console.error('Failed to add bookmark', e)
    }
  }

  // Trigger full pipeline analysis
  const runAnalysisPipeline = async () => {
    if (pipelineRunning) return
    
    setPipelineRunning(true)
    setPipelineProgress(5)
    
    // Reset stages
    setPipelineStages(prev => prev.map(s => ({ ...s, status: 'pending' })))

    try {
      // Simulate stages progress on client side to keep visual dashboard lively
      const stages = [...pipelineStages]
      let currentStageIndex = 0

      const progressInterval = setInterval(() => {
        if (currentStageIndex < stages.length - 1) {
          // Set current stage running
          setPipelineStages(prev =>
            prev.map((s, idx) => {
              if (idx === currentStageIndex) return { ...s, status: 'running' }
              if (idx < currentStageIndex) return { ...s, status: 'completed' }
              return s
            })
          )
          setPipelineProgress(Math.min(90, Math.floor(((currentStageIndex + 1) / stages.length) * 100)))
          currentStageIndex++
        } else {
          clearInterval(progressInterval)
        }
      }, 1500)

      // Make actual backend API request
      const response = await neuralApi.triggerAnalysis(scanId)
      
      clearInterval(progressInterval)

      if (response.status === 'complete') {
        setPipelineStages(prev => prev.map(s => ({ ...s, status: 'completed' })))
        setPipelineProgress(100)
        await loadScanData()
        await loadRiskAndSummary()
        await loadSandboxData()
      } else {
        throw new Error('Pipeline completed with failed status')
      }
    } catch (err: any) {
      setError(err.message || 'Pipeline analysis failed')
      setPipelineStages(prev => prev.map(s => s.status === 'running' ? { ...s, status: 'failed' } : s))
    } finally {
      setPipelineRunning(false)
    }
  }

  // Handle SSE chat message delivery
  const sendChatMessage = async (message: string) => {
    console.log("[Neural Lab] 1. Submit handler entered", { message });
    if (!message.trim() || chatLoading) return

    const userMsg: ChatMessage = {
      id: Math.random().toString(),
      role: 'user',
      content: message,
      timestamp: new Date().toLocaleTimeString(),
    }
    
    const botMsg: ChatMessage = {
      id: Math.random().toString(),
      role: 'assistant',
      content: '',
      timestamp: new Date().toLocaleTimeString(),
      isStreaming: true,
    }

    setChatMessages(prev => [...prev, userMsg, botMsg])
    setChatLoading(true)

    // Cancel previous stream if active
    if (chatAbortRef.current) {
      chatAbortRef.current()
    }

    console.log("[Neural Lab] 2. Request payload built", { scanId, message });
    const abort = neuralApi.chatStream(
      scanId,
      message,
      (token) => {
        console.log("[Neural Lab] Token received", { token });
        // Token received -> append token to botMsg content
        setChatMessages((prev) =>
          prev.map((msg) =>
            msg.id === botMsg.id ? { ...msg, content: msg.content + token } : msg
          )
        )
      },
      () => {
        console.log("[Neural Lab] Streaming Done");
        // Streaming Done
        setChatMessages((prev) =>
          prev.map((msg) =>
            msg.id === botMsg.id ? { ...msg, isStreaming: false } : msg
          )
        )
        setChatLoading(false)
        chatAbortRef.current = null
      },
      (err) => {
        // Streaming Error
        console.error("Forensic Chat connection error:", err)
        console.log("[Neural Lab] Streaming Error", { err });
        const errorDetail = err.message || "Connection Interrupted"
        setChatMessages((prev) =>
          prev.map((msg) =>
            msg.id === botMsg.id
              ? {
                  ...msg,
                  content: msg.content + `\n\n[Forensic Assistant Offline — ${errorDetail}]`,
                  isStreaming: false,
                }
              : msg
          )
        )
        setChatLoading(false)
        chatAbortRef.current = null
      }
    )

    chatAbortRef.current = abort
  }

  // Cancel any active LLM streams on component unmount
  useEffect(() => {
    return () => {
      if (chatAbortRef.current) {
        chatAbortRef.current()
      }
    }
  }, [])

  // Initial load effect
  useEffect(() => {
    if (scanId) {
      loadScanData()
      loadInvestigations()
    }
  }, [scanId, loadScanData, loadInvestigations])

  return {
    scan,
    loading,
    error,
    healthStatus,
    
    // Pipeline
    pipelineRunning,
    pipelineStages,
    pipelineProgress,
    runAnalysisPipeline,

    // Threat cognition metrics
    riskData,
    aiSummary,
    sandboxData,
    refreshRiskMetrics: loadRiskAndSummary,

    // Investigation Sessions
    investigations,
    activeInvestigation,
    notes,
    bookmarks,
    switchInvestigation,
    createInvestigation,
    updateActiveInvestigation,
    addNote,
    addBookmark,

    // AI Chat Panel
    chatMessages,
    chatLoading,
    sendChatMessage,
    clearChatHistory: () => setChatMessages([]),
  }
}
