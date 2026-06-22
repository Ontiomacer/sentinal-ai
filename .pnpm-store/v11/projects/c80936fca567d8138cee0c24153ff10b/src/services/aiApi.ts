import api from './api'

export interface AISuggestion {
  id: string
  title: string
  detail: string
  severity: string
  source: string
  action?: string | null
  route?: string | null
  metadata: Record<string, any>
}

export interface AISuggestionsResponse {
  generated_at: string
  ai_powered: boolean
  health: {
    healthy?: boolean
    ollama_running?: boolean
    model_available?: boolean
    model?: string
    error?: string
    [key: string]: any
  }
  scope: {
    case_id?: string | null
    evidence_id?: string | null
    scan_id?: string | null
  }
  suggestions: AISuggestion[]
  evidence_count: number
  timeline_count: number
  entity_count: number
  note_count: number
  model_summary?: string | null
}

export interface AIExplainResponse {
  ai_powered: boolean
  explanation: string
  health: Record<string, any>
  function_name?: string | null
  interpretation: {
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
}

export const aiApi = {
  health: async (): Promise<Record<string, any>> => {
    const response = await api.get('/api/v1/ai/health')
    return response.data
  },

  suggestions: async (payload: {
    case_id?: string
    evidence_id?: string
    scan_id?: string
    context?: Record<string, any>
    use_ai?: boolean
  }): Promise<AISuggestionsResponse> => {
    const response = await api.post<AISuggestionsResponse>('/api/v1/ai/suggestions', payload)
    return response.data
  },

  explain: async (payload: {
    code: string
    scan_id?: string
    function_name?: string
    context?: Record<string, any>
  }): Promise<AIExplainResponse> => {
    const response = await api.post<AIExplainResponse>('/api/v1/ai/explain', payload)
    return response.data
  },
}
