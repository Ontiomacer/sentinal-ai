/**
 * Advanced Runtime Monitoring
 * Real-time monitoring of permissions, overlays, services, network
 */

import React, { useState, useEffect } from 'react'

interface Props {
  device: any
  package?: string
}

const AdvancedRuntimeMonitor: React.FC<Props> = ({ device, package: packageName }) => {
  const [activeTab, setActiveTab] = useState<'permissions' | 'overlays' | 'accessibility' | 'services' | 'network' | 'processes'>('permissions')
  const [data, setData] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(true)

  useEffect(() => {
    if (device && autoRefresh) {
      loadData()
      const interval = setInterval(loadData, 5000) // Refresh every 5s
      return () => clearInterval(interval)
    }
  }, [device, activeTab, packageName, autoRefresh])

  const loadData = async () => {
    if (!device) return
    
    setLoading(true)
    try {
      let endpoint = ''
      
      switch (activeTab) {
        case 'permissions':
          if (!packageName) return
          endpoint = `/api/v1/device-lab/runtime/permissions?serial=${device.serial}&package=${packageName}`
          break
        case 'overlays':
          endpoint = `/api/v1/device-lab/runtime/overlays?serial=${device.serial}`
          break
        case 'accessibility':
          endpoint = `/api/v1/device-lab/runtime/accessibility?serial=${device.serial}`
          break
        case 'services':
          endpoint = `/api/v1/device-lab/runtime/services?serial=${device.serial}${packageName ? `&package=${packageName}` : ''}`
          break
        case 'network':
          endpoint = `/api/v1/device-lab/runtime/network?serial=${device.serial}`
          break
        case 'processes':
          endpoint = `/api/v1/device-lab/runtime/processes?serial=${device.serial}`
          break
      }
      
      const response = await fetch(endpoint)
      const result = await response.json()
      
      if (result.success) {
        setData(result)
      }
    } catch (error) {
      console.error('Failed to load runtime data:', error)
    } finally {
      setLoading(false)
    }
  }

  const renderContent = () => {
    if (!data) {
      return (
        <div className="flex items-center justify-center h-full">
          <p className="text-sm text-gray-600">No data available</p>
        </div>
      )
    }

    switch (activeTab) {
      case 'permissions':
        return renderPermissions()
      case 'overlays':
        return renderOverlays()
      case 'accessibility':
        return renderAccessibility()
      case 'services':
        return renderServices()
      case 'network':
        return renderNetwork()
      case 'processes':
        return renderProcesses()
    }
  }

  const renderPermissions = () => {
    const perms = data.data?.runtime_permissions || []
    
    return (
      <div className="divide-y divide-green-900/30">
        {perms.map((perm: any, idx: number) => (
          <div key={idx} className="p-3 hover:bg-[#1a1f2e]">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${perm.granted ? 'bg-green-500' : 'bg-red-500'}`}></span>
                <span className="font-mono text-sm text-gray-300">{perm.permission}</span>
              </div>
              <span className={`text-xs font-mono ${perm.granted ? 'text-green-400' : 'text-red-400'}`}>
                {perm.granted ? 'GRANTED' : 'DENIED'}
              </span>
            </div>
            {perm.flags && perm.flags.length > 0 && (
              <div className="flex gap-1 mt-2">
                {perm.flags.map((flag: string, i: number) => (
                  <span key={i} className="px-1.5 py-0.5 bg-blue-900/30 text-blue-400 text-[10px] font-mono rounded">
                    {flag}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    )
  }

  const renderOverlays = () => {
    const overlays = data.overlays || []
    
    if (overlays.length === 0) {
      return (
        <div className="flex items-center justify-center h-full">
          <div className="text-center">
            <span className="material-symbols-outlined text-6xl text-green-700 mb-2 block">check_circle</span>
            <p className="text-sm text-green-400">No overlay windows detected</p>
          </div>
        </div>
      )
    }
    
    return (
      <div className="divide-y divide-green-900/30">
        {overlays.map((overlay: any, idx: number) => (
          <div key={idx} className="p-3 bg-red-900/10">
            <div className="flex items-start gap-2">
              <span className="material-symbols-outlined text-base text-red-400 mt-0.5">warning</span>
              <div className="flex-1">
                <div className="font-mono text-sm text-red-400 mb-1">{overlay.package}</div>
                <div className="text-xs text-gray-500">{overlay.type}</div>
                {overlay.active && (
                  <span className="inline-block mt-2 px-2 py-1 bg-red-900/30 text-red-400 text-[10px] font-mono rounded">
                    ACTIVE NOW
                  </span>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    )
  }

  const renderAccessibility = () => {
    const services = data.services || []
    
    if (services.length === 0) {
      return (
        <div className="flex items-center justify-center h-full">
          <p className="text-sm text-gray-600">No accessibility services found</p>
        </div>
      )
    }
    
    return (
      <div className="divide-y divide-green-900/30">
        {services.map((service: any, idx: number) => (
          <div key={idx} className={`p-3 ${service.enabled ? 'bg-yellow-900/10' : ''}`}>
            <div className="flex items-start gap-2">
              {service.enabled && (
                <span className="material-symbols-outlined text-base text-yellow-400 mt-0.5">warning</span>
              )}
              <div className="flex-1">
                <div className="font-mono text-sm text-gray-300 mb-1">{service.package}</div>
                <div className="text-xs text-gray-600 mb-2">{service.component}</div>
                {service.capabilities && service.capabilities.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {service.capabilities.map((cap: string, i: number) => (
                      <span key={i} className="px-1.5 py-0.5 bg-red-900/30 text-red-400 text-[10px] font-mono rounded">
                        {cap}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              {service.enabled && (
                <span className="px-2 py-1 bg-yellow-900/30 text-yellow-400 text-[10px] font-mono rounded">
                  ENABLED
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    )
  }

  const renderServices = () => {
    const services = data.services || []
    
    return (
      <div className="divide-y divide-green-900/30">
        {services.map((service: any, idx: number) => (
          <div key={idx} className="p-3 hover:bg-[#1a1f2e]">
            <div className="flex items-center justify-between mb-1">
              <span className="font-mono text-sm text-gray-300">{service.package}</span>
              {service.pid && (
                <span className="text-xs font-mono text-gray-600">PID: {service.pid}</span>
              )}
            </div>
            <div className="text-xs text-gray-600">{service.service}</div>
          </div>
        ))}
      </div>
    )
  }

  const renderNetwork = () => {
    const connections = data.connections || []
    
    return (
      <div className="divide-y divide-green-900/30">
        {connections.map((conn: any, idx: number) => (
          <div key={idx} className="p-3 hover:bg-[#1a1f2e]">
            <div className="flex items-center justify-between mb-1">
              <span className="font-mono text-sm text-gray-300">
                {conn.remote.ip}:{conn.remote.port}
              </span>
              <span className="px-2 py-0.5 bg-green-900/30 text-green-400 text-[10px] font-mono rounded">
                {conn.protocol}
              </span>
            </div>
            <div className="text-xs text-gray-600">
              Local: {conn.local.ip}:{conn.local.port}
            </div>
          </div>
        ))}
      </div>
    )
  }

  const renderProcesses = () => {
    const processes = data.processes || []
    
    return (
      <div className="divide-y divide-green-900/30">
        {processes.map((proc: any, idx: number) => (
          <div key={idx} className="p-3 hover:bg-[#1a1f2e]">
            <div className="flex items-center justify-between mb-1">
              <span className="font-mono text-sm text-gray-300">{proc.name}</span>
              <span className="text-xs font-mono text-gray-600">PID: {proc.pid}</span>
            </div>
            <div className="flex gap-4 text-xs text-gray-600">
              <span>User: {proc.user}</span>
              <span>RSS: {proc.rss}</span>
            </div>
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className="h-full flex flex-col bg-[#0f1419]">
      {/* Header with Tabs */}
      <div className="flex-shrink-0">
        <div className="h-12 bg-[#1a1f2e] border-b border-green-900/30 flex items-center justify-between px-4">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-sm text-green-400">monitoring</span>
            <span className="font-mono text-xs uppercase tracking-wider text-gray-400">
              Advanced Runtime
            </span>
          </div>
          
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="rounded"
              />
              Auto-refresh
            </label>
            
            <button
              onClick={loadData}
              disabled={loading}
              className="p-1.5 hover:bg-green-900/20 rounded transition-colors disabled:opacity-50"
            >
              <span className="material-symbols-outlined text-sm text-gray-400">refresh</span>
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex bg-[#1a1f2e] border-b border-green-900/30 overflow-x-auto">
          {[
            { id: 'permissions', label: 'Permissions', icon: 'lock' },
            { id: 'overlays', label: 'Overlays', icon: 'layers' },
            { id: 'accessibility', label: 'Accessibility', icon: 'accessibility' },
            { id: 'services', label: 'Services', icon: 'settings' },
            { id: 'network', label: 'Network', icon: 'wifi' },
            { id: 'processes', label: 'Processes', icon: 'memory' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs font-mono whitespace-nowrap transition-colors ${
                activeTab === tab.id
                  ? 'text-green-400 bg-[#0f1419] border-b-2 border-green-500'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              <span className="material-symbols-outlined text-sm">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {loading && !data ? (
          <div className="flex items-center justify-center h-full">
            <div className="w-12 h-12 border-4 border-green-500/30 border-t-green-500 rounded-full animate-spin"></div>
          </div>
        ) : (
          renderContent()
        )}
      </div>
    </div>
  )
}

export default AdvancedRuntimeMonitor
