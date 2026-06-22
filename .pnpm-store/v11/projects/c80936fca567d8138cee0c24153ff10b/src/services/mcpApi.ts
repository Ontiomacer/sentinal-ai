/**
 * MCP & System Health API Service
 * 
 * Aggregates health checks and provides MCP tool discovery/invocation.
 */

import api from './api'

// ─── Types ───────────────────────────────────────────────────────────────────

export interface SystemHealthStatus {
  backend: { status: string; healthy: boolean }
  ghidra: {
    status: string
    connected: boolean
    tools_count: number
    latency_ms: number | null
  }
  ai: {
    healthy: boolean
    ollama_running: boolean
    model_available: boolean
  }
  database: { status: string }
}

export interface McpServerInfo {
  id: string
  name: string
  url: string
  transport: string
  status: 'connected' | 'disconnected' | 'error'
  tools_count: number
  latency_ms: number | null
  last_heartbeat: string | null
  capabilities: {
    decompiler?: boolean
    debugger?: boolean
    [key: string]: boolean | undefined
  }
  description?: string
  source?: string
  version?: string | null
  install?: Record<string, any>
  metadata?: Record<string, any>
}

export interface McpTool {
  name: string
  description: string
  input_schema: Record<string, any>
  category: string
  server_id: string
}

export interface McpInvocationResult {
  tool: string
  success: boolean
  result: any
  duration_ms: number
  error?: string
}

// ─── API ─────────────────────────────────────────────────────────────────────

export const mcpApi = {
  /**
   * Aggregate system health from all subsystems.
   */
  getSystemHealth: async (): Promise<SystemHealthStatus> => {
    const [backendRes, mcpRes, aiRes] = await Promise.allSettled([
      api.get('/health'),
      api.get('/api/v1/debug/mcp'),
      api.get('/api/v1/neural/health'),
    ])

    const backend =
      backendRes.status === 'fulfilled'
        ? { status: 'online', healthy: true }
        : { status: 'offline', healthy: false }

    const discovered =
      mcpRes.status === 'fulfilled'
        ? mcpRes.value.data.tools_discovered
        : 0

    const toolCount = Array.isArray(discovered)
      ? discovered.length
      : typeof discovered === 'number'
        ? discovered
        : 0

    const mcp =
      mcpRes.status === 'fulfilled'
        ? {
            status: mcpRes.value.data.status || 'unknown',
            connected: mcpRes.value.data.transport_online ?? false,
            tools_count: toolCount,
            latency_ms: mcpRes.value.data.latency_ms ?? null,
          }
        : { status: 'offline', connected: false, tools_count: 0, latency_ms: null }

    const ai =
      aiRes.status === 'fulfilled'
        ? aiRes.value.data
        : { healthy: false, ollama_running: false, model_available: false }

    return {
      backend,
      ghidra: mcp,
      ai,
      database: { status: backend.healthy ? 'online' : 'unknown' },
    }
  },

  /**
   * Get MCP server registry (known servers and their status).
   */
  getMcpServers: async (query?: string, limit: number = 25): Promise<McpServerInfo[]> => {
    try {
      const response = await api.get('/api/v1/mcp/registry', {
        params: { query, limit },
      })
      return response.data
    } catch {
      return []
    }
  },

  /**
   * Get all discovered MCP tools.
   */
  getMcpTools: async (): Promise<McpTool[]> => {
    try {
      const response = await api.get('/api/v1/mcp/tools')
      return response.data
    } catch {
      return []
    }
  },

  /**
   * Invoke an MCP tool by name.
   */
  invokeMcpTool: async (
    toolName: string,
    args: Record<string, any>
  ): Promise<McpInvocationResult> => {
    const response = await api.post<McpInvocationResult>('/api/v1/mcp/invoke', {
      tool_name: toolName,
      arguments: args,
    })
    return response.data
  },

  /**
   * Get MCP connection status (lightweight).
   */
  getMcpStatus: async (): Promise<{
    transport_online: boolean
    status: string
    tools_discovered: string[]
  }> => {
    const response = await api.get('/api/v1/debug/mcp')
    return response.data
  },
}
