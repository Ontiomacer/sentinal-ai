import api from './api'

export interface NeuralAnalysisResponse {
  scan_id: string
  status: 'complete' | 'failed' | 'analyzing'
  stages_completed: string[]
  total_stages: number
  yara_matches: number
  ai_available: boolean
}

export interface RiskAssessmentResponse {
  scan_id: string
  banking_intelligence: {
    ai_powered: boolean
    overall_risk: number
    threat_classification: string
    fraud_intent: string
    executive_summary: string
    banking_impact_assessment: {
      targeted_apps: string[]
      impact_summary: string
      fraud_vectors: string[]
    }
    technical_findings: string[]
    mitre_attack_mapping: any[]
    risk_factors: string[]
    indicators_of_compromise: string[]
    recommended_actions: string[]
    fraud_prevention_recommendations: string[]
    targeted_banking_apps: string[]
    top_suspicious_functions: Array<{
      function_name: string
      class_name: string
      risk_score: number
      reason: string
    }>
    fraud_scores: {
      overall_risk: number
      credential_theft: number
      otp_theft: number
      upi_fraud: number
      account_takeover: number
      financial_data_exposure: number
    }
    confidence_score: number
  }
  ai_powered: boolean
}

export interface ExplainResponse {
  scan_id: string
  explanation: string
  interpretation?: {
    status?: string
    purpose?: string
    behavior?: string
    security_impact?: string
    fraud_impact?: string
    confidence?: number
    evidence?: string[]
    matched_behaviors?: any[]
    [key: string]: any
  }
  ai_powered: boolean
  function_name?: string
}

export interface Investigation {
  id: string
  scan_id: string
  title: string
  description: string
  status: 'active' | 'paused' | 'completed' | 'archived'
  analyst_name: string
  created_at: string
  updated_at: string
  threat_level: string
  risk_score: number
  malware_family: string
  notes_count: number
  bookmarks_count: number
}

export interface RecentInvestigation extends Investigation {
  filename: string
  app_name: string
  has_neural_analysis: boolean
}

export interface InvestigationNote {
  id: string
  investigation_id: string
  content: string
  note_type: 'general' | 'finding' | 'question' | 'action'
  tags: string[]
  created_at: string
}

export interface InvestigationBookmark {
  id: string
  investigation_id: string
  target_type: 'function' | 'ioc' | 'pattern' | 'api' | 'string'
  target_id: string
  label: string
  notes: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  created_at: string
}

export interface SandboxEvent {
  timestamp: string
  type: string
  category: string
  event: string
  summary: string
  detail: string
  severity: 'low' | 'medium' | 'high' | 'critical'
}

export interface SandboxTimelineItem {
  time: string
  title: string
  description: string
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
}

export interface SandboxResponse {
  scan_id: string
  sandbox: {
    events: SandboxEvent[]
    statistics: {
      duration_seconds: number
      total_events: number
      critical_events: number
      high_events: number
      network_requests: number
      file_writes: number
      permission_abuses: number
    }
    timeline: SandboxTimelineItem[]
  }
}

export interface ReportResponse {
  scan_id: string
  report_type: string
  report: any
}

export const neuralApi = {
  triggerAnalysis: async (scanId: string): Promise<NeuralAnalysisResponse> => {
    const response = await api.post<NeuralAnalysisResponse>('/api/v1/neural/analyze', { scan_id: scanId })
    return response.data
  },

  getSummary: async (scanId: string): Promise<{ scan_id: string; summary: string; ai_powered: boolean }> => {
    const response = await api.get<{ scan_id: string; summary: string; ai_powered: boolean }>(`/api/v1/neural/summary/${scanId}`)
    return response.data
  },

  getRisk: async (scanId: string): Promise<RiskAssessmentResponse> => {
    const response = await api.get<RiskAssessmentResponse>(`/api/v1/neural/risk/${scanId}`)
    return response.data
  },

  explainCode: async (
    scanId: string,
    code: string,
    functionName?: string,
    contextHint?: string
  ): Promise<ExplainResponse> => {
    const response = await api.post<ExplainResponse>('/api/v1/neural/explain', {
      scan_id: scanId,
      code,
      function_name: functionName,
      context_hint: contextHint,
    })
    return response.data
  },

  // SSE Chat stream helper
  chatStream: (
    scanId: string,
    message: string,
    onToken: (token: string) => void,
    onDone: () => void,
    onError: (err: any) => void
  ) => {
    console.log("[Neural Lab] 3. API function called", { scanId, message });
    const baseURL = api.defaults.baseURL || import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || ''
    const url = `${baseURL}/api/v1/neural/chat`
    
    console.log(`[Neural Chat] Initiating stream to ${url}`, { scanId, message_len: message.length })
    
    const controller = new AbortController()
    
    console.log("[Neural Lab] 4. Request dispatched", { url, scanId });
    fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ scan_id: scanId, message, stream: true }),
      signal: controller.signal,
    })
      .then(async (response) => {
        console.log(`[Neural Chat] Response status: ${response.status} ${response.statusText}`)
        
        const contentType = response.headers.get('content-type')
        console.log(`[Neural Chat] Content-Type: ${contentType}`)

        if (!response.ok) {
          try {
            const data = await response.json()
            const detail = data.detail || `HTTP error! status: ${response.status}`
            console.error(`[Neural Chat] Error detail: ${detail}`)
            onError(new Error(detail))
          } catch (e) {
            console.error(`[Neural Chat] HTTP error: ${response.status}`)
            onError(new Error(`HTTP error! status: ${response.status}`))
          }
          return
        }
        
        if (!response.body) {
          console.error(`[Neural Chat] No response body for stream`)
          throw new Error('ReadableStream not supported')
        }
        const reader = response.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ''

        function read() {
          reader.read().then(({ done, value }) => {
            if (done) {
              onDone()
              return
            }
            
            buffer += decoder.decode(value, { stream: true })
            const lines = buffer.split('\n')
            buffer = lines.pop() || ''

            for (const line of lines) {
              const cleaned = line.trim()
              if (!cleaned.startsWith('data: ')) continue
              
              try {
                const data = JSON.parse(cleaned.substring(6))
                if (data.token) {
                  onToken(data.token)
                }
                if (data.done) {
                  console.log(`[Neural Chat] Stream complete (done=true signal)`)
                  onDone()
                  return
                }
                if (data.error) {
                  console.error(`[Neural Chat] Stream error signal: ${data.error}`)
                  onError(new Error(data.error))
                  return
                }
              } catch (e) {
                console.warn(`[Neural Chat] JSON parse error in stream: ${e}, Line: ${cleaned}`)
              }
            }
            
            read()
          }).catch(onError)
        }

        read()
      })
      .catch(onError)

    return () => controller.abort()
  },

  // Investigations CRUD
  listInvestigations: async (scanId?: string): Promise<Investigation[]> => {
    const response = await api.get<Investigation[]>('/api/v1/neural/investigations', {
      params: scanId ? { scan_id: scanId } : {},
    })
    return response.data
  },

  createInvestigation: async (
    scanId: string,
    title: string,
    description: string,
    analystName: string
  ): Promise<Investigation> => {
    const response = await api.post<Investigation>('/api/v1/neural/investigations', {
      scan_id: scanId,
      title,
      description,
      analyst_name: analystName,
    })
    return response.data
  },

  getInvestigation: async (id: string): Promise<Investigation> => {
    const response = await api.get<Investigation>(`/api/v1/neural/investigations/${id}`)
    return response.data
  },

  updateInvestigation: async (id: string, payload: Partial<Investigation>): Promise<Investigation> => {
    const response = await api.put<Investigation>(`/api/v1/neural/investigations/${id}`, payload)
    return response.data
  },

  deleteInvestigation: async (id: string): Promise<{ deleted: boolean }> => {
    const response = await api.delete<{ deleted: boolean }>(`/api/v1/neural/investigations/${id}`)
    return response.data
  },

  // Notes
  listNotes: async (investigationId: string): Promise<InvestigationNote[]> => {
    const response = await api.get<InvestigationNote[]>(`/api/v1/neural/investigations/${investigationId}/notes`)
    return response.data
  },

  addNote: async (
    investigationId: string,
    content: string,
    noteType: string = 'general',
    tags: string[] = []
  ): Promise<InvestigationNote> => {
    const response = await api.post<InvestigationNote>(`/api/v1/neural/investigations/${investigationId}/notes`, {
      content,
      note_type: noteType,
      tags,
    })
    return response.data
  },

  // Bookmarks
  listBookmarks: async (investigationId: string): Promise<InvestigationBookmark[]> => {
    const response = await api.get<InvestigationBookmark[]>(`/api/v1/neural/investigations/${investigationId}/bookmarks`)
    return response.data
  },

  addBookmark: async (
    investigationId: string,
    targetType: string,
    targetId: string,
    label: string = '',
    notes: string = '',
    severity: string = 'medium'
  ): Promise<InvestigationBookmark> => {
    const response = await api.post<InvestigationBookmark>(`/api/v1/neural/investigations/${investigationId}/bookmarks`, {
      target_type: targetType,
      target_id: targetId,
      label,
      notes,
      severity,
    })
    return response.data
  },

  // Report
  getReport: async (scanId: string, reportType: string): Promise<ReportResponse> => {
    const response = await api.post<ReportResponse>('/api/v1/neural/report', {
      scan_id: scanId,
      report_type: reportType,
    })
    return response.data
  },

  // Static runtime reconstruction
  getSandboxTimeline: async (scanId: string): Promise<SandboxResponse> => {
    const response = await api.get<SandboxResponse>(`/api/v1/neural/sandbox/${scanId}`)
    return response.data
  },

  // Health / general status check
  getHealth: async (): Promise<{ healthy: boolean; ollama_running: boolean; model_available: boolean }> => {
    const response = await api.get<{ healthy: boolean; ollama_running: boolean; model_available: boolean }>('/api/v1/neural/health')
    return response.data
  },

  getRecentInvestigations: async (): Promise<RecentInvestigation[]> => {
    const response = await api.get<RecentInvestigation[]>('/api/v1/neural/investigations/recent')
    return response.data
  },

  bridgeEvidence: async (
    caseId: string,
    evidenceId: string
  ): Promise<{
    scan_id: string
    filename: string
    status: string
    evidence_id: string
    case_id: string
  }> => {
    const response = await api.post<{
      scan_id: string
      filename: string
      status: string
      evidence_id: string
      case_id: string
    }>('/api/v1/neural/bridge-evidence', {
      case_id: caseId,
      evidence_id: evidenceId,
    })
    return response.data
  },
}
