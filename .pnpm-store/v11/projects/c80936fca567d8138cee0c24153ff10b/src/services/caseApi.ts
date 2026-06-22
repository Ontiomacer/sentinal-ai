import axios from 'axios'
import { getAuthToken } from './auth'

const API_BASE_URL = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
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
export interface CaseResponse {
  id: string
  name: string
  client_name?: string
  investigator: string
  description?: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'active' | 'archived' | 'closed' | 'pending'
  tags?: string[]
  user_id: string
  case_directory: string
  created_at: string
  updated_at?: string
  closed_at?: string
  evidence_count: number
  timeline_count: number
  entity_count: number
  note_count: number
}

export interface CaseFileNode {
  id: string
  name: string
  relative_path: string
  kind: 'directory' | 'file'
  size: number
  modified_at: string
  evidence_id?: string
  evidence_type?: string
  sha256?: string
  children: CaseFileNode[]
}

export interface CaseDirectoryStatus {
  name: string
  relative_path: string
  exists: boolean
  file_count: number
  size: number
}

export interface CaseFilesystem {
  case_id: string
  root_path: string
  tree: CaseFileNode
  expected_directories: CaseDirectoryStatus[]
  totals: {
    directories: number
    files: number
    bytes: number
    evidence_items: number
  }
}

export interface TriageFile {
  name: string
  path: string
  size: number
  modified_at: string
}

export interface TriageDrive {
  name: string
  path: string
  status: 'ready' | 'missing' | string
  is_case_triage: boolean
  file_count: number
  size: number
  last_seen: string
  files: TriageFile[]
}

export interface CaseTriage {
  case_id: string
  drives: TriageDrive[]
  configured_roots_env: string
}

export interface CaseReportItem {
  id: string
  name: string
  report_type: 'executive' | 'technical' | 'timeline' | 'ioc' | string
  relative_path: string
  size: number
  modified_at: string
  sha256?: string
}

export interface CaseReportInventory {
  case_id: string
  reports: CaseReportItem[]
  count: number
}

export interface CaseCreate {
  name: string
  client_name?: string
  investigator: string
  description?: string
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  tags?: string[]
}

export interface CaseUpdate {
  name?: string
  client_name?: string
  investigator?: string
  description?: string
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status?: 'active' | 'archived' | 'closed' | 'pending'
  tags?: string[]
}

export interface TimelineEvent {
  id: string
  case_id: string
  event_type: string
  title: string
  description?: string
  evidence_id?: string
  entity_id?: string
  user_id: string
  metadata?: any
  created_at: string
}

export interface Entity {
  id: string
  case_id: string
  entity_type: 'person' | 'domain' | 'url' | 'wallet' | 'apk' | 'organization' | 'ip_address' | 'email' | 'phone'
  name: string
  value: string
  description?: string
  risk_score?: number
  tags?: string[]
  related_evidence?: string[]
  metadata?: any
  created_at: string
  updated_at?: string
}

export interface CaseNote {
  id: string
  case_id: string
  title: string
  content: string
  note_type: string
  user_id: string
  author_name: string
  created_at: string
  updated_at?: string
}

// Case API
export const createCase = async (data: CaseCreate): Promise<CaseResponse> => {
  const response = await api.post('/cases', data)
  return response.data
}

export const listCases = async (status?: string): Promise<CaseResponse[]> => {
  const params = status ? { status } : {}
  const response = await api.get('/cases', { params })
  return response.data
}

export const getCase = async (caseId: string): Promise<CaseResponse> => {
  const response = await api.get(`/cases/${caseId}`)
  return response.data
}

export const updateCase = async (caseId: string, data: CaseUpdate): Promise<CaseResponse> => {
  const response = await api.patch(`/cases/${caseId}`, data)
  return response.data
}

export const archiveCase = async (caseId: string): Promise<CaseResponse> => {
  const response = await api.post(`/cases/${caseId}/archive`)
  return response.data
}

export const deleteCase = async (caseId: string): Promise<void> => {
  await api.delete(`/cases/${caseId}`)
}

export const getCaseFilesystem = async (caseId: string): Promise<CaseFilesystem> => {
  const response = await api.get(`/cases/${caseId}/filesystem`)
  return response.data
}

export const getCaseTriage = async (caseId: string): Promise<CaseTriage> => {
  const response = await api.get(`/cases/${caseId}/triage`)
  return response.data
}

export const importTriageFile = async (
  caseId: string,
  filePath: string
): Promise<any> => {
  const response = await api.post(`/cases/${caseId}/triage/import`, {
    file_path: filePath
  })
  return response.data
}

export const listCaseReports = async (caseId: string): Promise<CaseReportInventory> => {
  const response = await api.get(`/cases/${caseId}/reports/inventory`)
  return response.data
}

export const generateCaseReport = async (
  caseId: string,
  reportType: 'executive' | 'technical' | 'timeline' | 'ioc'
): Promise<CaseReportItem> => {
  const response = await api.post(`/cases/${caseId}/reports/generate`, {
    report_type: reportType
  })
  return response.data
}

export const getCaseReportContent = async (
  caseId: string,
  reportName: string
): Promise<{ content: string }> => {
  const response = await api.get(`/cases/${caseId}/reports/${reportName}/content`)
  return response.data
}

// Timeline API
export const listTimelineEvents = async (caseId: string): Promise<TimelineEvent[]> => {
  const response = await api.get(`/cases/${caseId}/timeline`)
  return response.data
}

export const createTimelineEvent = async (caseId: string, data: any): Promise<TimelineEvent> => {
  const response = await api.post(`/cases/${caseId}/timeline`, data)
  return response.data
}

// Entity API
export const listEntities = async (caseId: string): Promise<Entity[]> => {
  const response = await api.get(`/cases/${caseId}/entities`)
  return response.data
}

export const createEntity = async (caseId: string, data: any): Promise<Entity> => {
  const response = await api.post(`/cases/${caseId}/entities`, data)
  return response.data
}

export const updateEntity = async (caseId: string, entityId: string, data: any): Promise<Entity> => {
  const response = await api.patch(`/cases/${caseId}/entities/${entityId}`, data)
  return response.data
}

// Note API
export const listNotes = async (caseId: string): Promise<CaseNote[]> => {
  const response = await api.get(`/cases/${caseId}/notes`)
  return response.data
}

export const createNote = async (caseId: string, data: any): Promise<CaseNote> => {
  const response = await api.post(`/cases/${caseId}/notes`, data)
  return response.data
}

export const updateNote = async (caseId: string, noteId: string, data: any): Promise<CaseNote> => {
  const response = await api.patch(`/cases/${caseId}/notes/${noteId}`, data)
  return response.data
}

export const deleteNote = async (caseId: string, noteId: string): Promise<void> => {
  await api.delete(`/cases/${caseId}/notes/${noteId}`)
}

// Evidence API
export interface Evidence {
  id: string
  case_id: string
  evidence_type: string
  filename: string
  original_filename: string
  file_size: number
  file_path: string
  md5?: string
  sha1?: string
  sha256: string
  analysis_status: string
  analysis_result?: any
  uploaded_by: string
  notes?: string
  created_at: string
  analyzed_at?: string
}

export const uploadEvidence = async (
  caseId: string,
  file: File,
  notes?: string
): Promise<Evidence> => {
  const formData = new FormData()
  formData.append('file', file)
  if (notes) {
    formData.append('notes', notes)
  }

  const response = await api.post(`/cases/${caseId}/evidence`, formData)
  return response.data
}

export const listEvidence = async (caseId: string): Promise<Evidence[]> => {
  const response = await api.get(`/cases/${caseId}/evidence`)
  return response.data
}

export const getEvidence = async (caseId: string, evidenceId: string): Promise<Evidence> => {
  const response = await api.get(`/cases/${caseId}/evidence/${evidenceId}`)
  return response.data
}

export const analyzeEvidence = async (
  caseId: string,
  evidenceId: string,
  pipeline: 'neural_ai' | 'deep_reverse_engineering'
): Promise<any> => {
  const formData = new FormData()
  formData.append('pipeline', pipeline)

  const response = await api.post(`/cases/${caseId}/evidence/${evidenceId}/analyze`, formData)
  return response.data
}

export const deleteEvidence = async (caseId: string, evidenceId: string): Promise<void> => {
  await api.delete(`/cases/${caseId}/evidence/${evidenceId}`)
}
