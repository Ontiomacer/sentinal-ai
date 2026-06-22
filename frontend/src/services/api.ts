import axios from 'axios'
import { getAuthToken } from './auth'

const API_BASE_URL = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

api.interceptors.request.use(async (config) => {
  const authToken = await getAuthToken()
  if (authToken) {
    config.headers.Authorization = `Bearer ${authToken}`
  }
  return config
})

// Types
export interface ScanResponse {
  scan_id: string
  sha256: string
  filename: string
  file_size: number
  status: 'analyzing' | 'completed' | 'failed'
  created_at: string
  analysis_result?: AnalysisResult
}

export interface AnalysisResult {
  package_name?: string
  app_name?: string
  version_name?: string
  version_code?: string
  min_sdk_version?: string
  target_sdk_version?: string
  permissions?: Permission[]
  activities?: Component[]
  services?: Component[]
  receivers?: Component[]
  providers?: Component[]
  files?: FileInfo
  libraries?: string[]
  is_signed?: boolean
  is_valid_apk?: boolean
  main_activity?: string
  risk_assessment?: RiskAssessment
  threat_assessment?: RiskAssessment
  threat_classification?: {
    threat_type: string
    threat_family: string
    confidence: number
    evidence: string[]
    [key: string]: any
  }
  fraud_intent?: {
    objectives: any[]
    summary: string
    [key: string]: any
  }
  attack_flow?: {
    steps: any[]
    summary: string
    [key: string]: any
  }
  recommendations?: any[]
  apk_analysis?: any
  top_suspicious_functions?: any[]
  neural_analysis?: any
  error?: string
  analysis_failed?: boolean
}

export interface Permission {
  name: string
  category: 'dangerous' | 'network' | 'system' | 'normal'
}

export interface Component {
  name: string
  is_exported?: boolean | null
}

export interface FileInfo {
  total_files: number
  dex_files: string[]
  so_files: string[]
  has_native_code: boolean
  has_assets: boolean
  has_resources: boolean
}

export interface RiskAssessment {
  risk_score: number
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  findings: string[]
  summary: string
  technical_risk_score?: number
  fraud_risk_score?: number
  overall_severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  contributors?: any[]
  score_breakdown: {
    [key: string]: number
  }
}

// API Methods
export const uploadAPK = async (file: File): Promise<ScanResponse> => {
  const formData = new FormData()
  formData.append('file', file)

  const response = await api.post<ScanResponse>('/api/v1/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })

  return response.data
}

export const getScan = async (scanId: string): Promise<ScanResponse> => {
  const response = await api.get<ScanResponse>(`/api/v1/scan/${scanId}`)
  return response.data
}

export interface ScanListParams {
  skip?: number
  limit?: number
}

export const listScans = async (params: ScanListParams = {}): Promise<ScanResponse[]> => {
  const response = await api.get<ScanResponse[]>('/api/v1/scans', { params })
  return response.data
}

export const healthCheck = async (): Promise<{ status: string }> => {
  const response = await api.get('/health')
  return response.data
}

export default api
