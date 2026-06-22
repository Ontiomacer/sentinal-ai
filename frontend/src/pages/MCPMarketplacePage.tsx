import { useEffect, useMemo, useState } from 'react'
import GlassPanel from '../components/ui/GlassPanel'
import { McpInvocationResult, McpServerInfo, McpTool, mcpApi } from '../services/mcpApi'

const statusTone = (status: string) => {
  if (status === 'connected') return 'bg-white text-black'
  if (status === 'error') return 'bg-black border border-white/40 text-white'
  return 'bg-white/10 text-on-surface-variant border border-white/10'
}

const MCPMarketplacePage = () => {
  const [servers, setServers] = useState<McpServerInfo[]>([])
  const [tools, setTools] = useState<McpTool[]>([])
  const [query, setQuery] = useState('cybersecurity')
  const [loading, setLoading] = useState(true)
  const [toolLoading, setToolLoading] = useState(false)
  const [invokeResult, setInvokeResult] = useState<McpInvocationResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const localServer = useMemo(
    () => servers.find((server) => server.source === 'local'),
    [servers],
  )

  const registryServers = useMemo(
    () => servers.filter((server) => server.source !== 'local'),
    [servers],
  )

  const load = async (search = query) => {
    try {
      setLoading(true)
      setError(null)
      const [serverData, toolData] = await Promise.all([
        mcpApi.getMcpServers(search),
        mcpApi.getMcpTools(),
      ])
      setServers(serverData)
      setTools(toolData)
    } catch (err: any) {
      setError(err?.message || 'MCP registry unavailable')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const runDiagnostics = async () => {
    try {
      setToolLoading(true)
      const result = await mcpApi.invokeMcpTool('ghidra.diagnostics', {})
      setInvokeResult(result)
    } catch (err: any) {
      setInvokeResult({
        tool: 'ghidra.diagnostics',
        success: false,
        result: null,
        duration_ms: 0,
        error: err?.message || 'Invocation failed',
      })
    } finally {
      setToolLoading(false)
    }
  }

  return (
    <div className="container-padding fade-in sentinel-mono">
      <section className="mb-8 max-w-7xl">
        <div className="mono-oath p-5 mb-6">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-5">
            <div>
              <div className="font-mono text-[11px] text-on-surface-variant tracking-[0.22em] mb-3">
                MCP MARKETPLACE / CLAUDE-READY INTEGRATION MAP
              </div>
              <h1 className="font-display-xl text-display-xl text-on-surface leading-tight">
                TOOLING SHOULD ANSWER TO EVIDENCE
              </h1>
              <p className="text-body-md text-on-surface-variant max-w-3xl mt-4">
                Local Ghidra MCP stays connected through Sentinel. Registry entries are pulled live from the official MCP Registry so analysts can discover integrations without leaving the workstation.
              </p>
            </div>
            <div className="border border-white/15 bg-black/45 p-4 min-w-[240px]">
              <div className="font-mono text-[10px] tracking-[0.16em] text-on-surface-variant mb-2">LOCAL TRANSPORT</div>
              <div className="font-mono text-2xl text-on-surface">
                {localServer?.status?.toUpperCase() || 'UNKNOWN'}
              </div>
              <div className="font-mono text-[11px] text-on-surface-variant mt-2">
                {localServer?.tools_count || 0} SENTINEL TOOLS
              </div>
            </div>
          </div>
        </div>

        <GlassPanel className="mono-panel p-4">
          <div className="flex flex-col md:flex-row gap-3 md:items-center">
            <div className="relative flex-1">
              <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant/60 text-[18px]">
                travel_explore
              </span>
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') load(query)
                }}
                className="w-full bg-black/50 border border-white/10 px-10 py-3 font-mono text-[12px] text-on-surface focus:outline-none focus:border-white/40"
                placeholder="Search official MCP registry..."
              />
            </div>
            <button
              onClick={() => load(query)}
              className="px-5 py-3 bg-white text-black font-mono text-[11px] tracking-[0.16em] hover:bg-white/80 transition-colors"
            >
              SEARCH REGISTRY
            </button>
            <button
              onClick={runDiagnostics}
              disabled={toolLoading}
              className="px-5 py-3 border border-white/20 font-mono text-[11px] tracking-[0.16em] text-on-surface hover:bg-white/10 transition-colors disabled:opacity-50"
            >
              {toolLoading ? 'RUNNING' : 'TEST GHIDRA MCP'}
            </button>
          </div>
        </GlassPanel>
      </section>

      {error && (
        <GlassPanel className="max-w-7xl p-4 mb-6 border-white/30">
          <p className="font-mono text-[12px] text-on-surface-variant">{error}</p>
        </GlassPanel>
      )}

      {invokeResult && (
        <section className="max-w-7xl mb-8">
          <GlassPanel className="mono-panel p-5">
            <div className="flex items-center justify-between gap-4 mb-3">
              <h2 className="font-title-md text-title-md text-on-surface">MCP CALL TRACE</h2>
              <span className={`px-3 py-1 font-mono text-[10px] ${invokeResult.success ? 'bg-white text-black' : 'border border-white/30 text-on-surface'}`}>
                {invokeResult.success ? 'SUCCESS' : 'FAILED'}
              </span>
            </div>
            <pre className="max-h-72 overflow-auto bg-black/60 border border-white/10 p-4 font-mono text-[12px] text-on-surface-variant custom-scrollbar">
              {JSON.stringify(invokeResult, null, 2)}
            </pre>
          </GlassPanel>
        </section>
      )}

      <section className="grid grid-cols-1 xl:grid-cols-3 gap-gutter max-w-7xl mb-8">
        <div className="xl:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-title-md text-title-md text-on-surface">LIVE MCP REGISTRY</h2>
            <span className="font-mono text-[11px] text-on-surface-variant">
              {loading ? 'SYNCING' : `${registryServers.length} RESULTS`}
            </span>
          </div>

          {loading ? (
            <GlassPanel className="mono-panel p-8 text-center">
              <span className="material-symbols-outlined animate-spin text-4xl text-on-surface mb-3 block">
                progress_activity
              </span>
              <p className="font-mono text-[12px] text-on-surface-variant">QUERYING OFFICIAL REGISTRY</p>
            </GlassPanel>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {registryServers.map((server) => (
                <div key={server.id} className="mcp-server-card mono-panel">
                  <div className="flex items-start justify-between gap-4 mb-4">
                    <div className="min-w-0">
                      <div className="font-mono text-[10px] text-on-surface-variant tracking-[0.18em] mb-1">
                        {server.source?.toUpperCase()} / {server.transport.toUpperCase()}
                      </div>
                      <h3 className="font-title-md text-[18px] leading-6 text-on-surface truncate">
                        {server.name}
                      </h3>
                    </div>
                    <span className={`px-2 py-1 font-mono text-[10px] shrink-0 ${statusTone(server.status)}`}>
                      {server.status.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-[13px] leading-6 text-on-surface-variant min-h-[72px]">
                    {server.description || 'No registry description is available for this server.'}
                  </p>
                  <div className="mt-4 border-t border-white/10 pt-3 space-y-2 font-mono text-[11px] text-on-surface-variant">
                    <div className="truncate">URL: {server.url}</div>
                    <div>VERSION: {server.version || 'latest'}</div>
                    <div>UPDATED: {server.last_heartbeat || 'unknown'}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <aside className="space-y-4">
          <GlassPanel className="mono-panel p-0 overflow-hidden">
            <div className="workstation-panel-header">
              <span className="material-symbols-outlined text-[18px]">memory</span>
              <span>LOCAL SENTINEL MCP</span>
            </div>
            <div className="p-5 space-y-4">
              <div>
                <div className="font-mono text-[10px] tracking-[0.16em] text-on-surface-variant mb-1">SERVER</div>
                <div className="font-mono text-on-surface break-all">{localServer?.url || 'offline'}</div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="border border-white/10 bg-black/30 p-3">
                  <div className="font-mono text-[10px] text-on-surface-variant">TOOLS</div>
                  <div className="font-mono text-2xl text-on-surface">{tools.length}</div>
                </div>
                <div className="border border-white/10 bg-black/30 p-3">
                  <div className="font-mono text-[10px] text-on-surface-variant">LATENCY</div>
                  <div className="font-mono text-2xl text-on-surface">
                    {localServer?.latency_ms ? Math.round(localServer.latency_ms) : 0}
                  </div>
                </div>
              </div>
              <pre className="bg-black/70 border border-white/10 p-3 font-mono text-[11px] text-on-surface-variant overflow-auto custom-scrollbar">
{JSON.stringify(localServer?.install?.claude_desktop || {
  name: 'ghidra-local',
  transport: 'http',
  url: localServer?.url || 'http://localhost:8089',
}, null, 2)}
              </pre>
            </div>
          </GlassPanel>

          <GlassPanel className="mono-panel p-0 overflow-hidden">
            <div className="workstation-panel-header">
              <span className="material-symbols-outlined text-[18px]">build</span>
              <span>SENTINEL TOOL SURFACE</span>
            </div>
            <div className="p-4 space-y-3 max-h-[520px] overflow-auto custom-scrollbar">
              {tools.map((tool) => (
                <div key={tool.name} className="mcp-tool-card">
                  <div className="font-mono text-[12px] text-on-surface mb-1">{tool.name}</div>
                  <div className="font-mono text-[10px] text-on-surface-variant tracking-[0.14em] mb-2">
                    {tool.category.toUpperCase()}
                  </div>
                  <p className="text-[12px] leading-5 text-on-surface-variant">{tool.description}</p>
                </div>
              ))}
            </div>
          </GlassPanel>
        </aside>
      </section>
    </div>
  )
}

export default MCPMarketplacePage
