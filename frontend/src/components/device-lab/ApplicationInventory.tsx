/**
 * Application Inventory Panel
 * Lists all installed applications with search and filter
 */

import React, { useState, useEffect } from 'react'

interface App {
  package: string
  label: string
  version_name: string
  version_code: string
  installer: string
  permissions: string[]
  is_system: boolean
  enabled: boolean
}

interface Props {
  device: any
}

const ApplicationInventory: React.FC<Props> = ({ device }) => {
  const [apps, setApps] = useState<App[]>([])
  const [loading, setLoading] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [showSystemApps, setShowSystemApps] = useState(false)
  const [selectedApp, setSelectedApp] = useState<App | null>(null)

  useEffect(() => {
    if (device) {
      loadApps()
    }
  }, [device, showSystemApps])

  const loadApps = async () => {
    if (!device) return
    
    setLoading(true)
    try {
      const response = await fetch(`/api/v1/device-lab/apps?serial=${device.serial}&include_system=${showSystemApps}`)
      const data = await response.json()
      
      if (data.success) {
        setApps(data.apps)
      }
    } catch (error) {
      console.error('Failed to load apps:', error)
    } finally {
      setLoading(false)
    }
  }

  const pullAPK = async (pkg: string) => {
    if (!device) return
    
    try {
      const response = await fetch('/api/v1/device-lab/apps/pull', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_serial: device.serial,
          package: pkg
        })
      })
      
      const data = await response.json()
      if (!response.ok) {
        throw new Error(data?.detail || data?.message || `APK pull failed with HTTP ${response.status}`)
      }
      if (data.success) {
        alert(`APK pulled successfully: ${data.path}`)
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.error('APK pull error:', message)
      alert(message)
    }
  }

  const filteredApps = apps.filter(app => 
    app.package.toLowerCase().includes(searchTerm.toLowerCase()) ||
    app.label?.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <div className="h-full flex flex-col bg-[#0f1419]">
      {/* Header */}
      <div className="h-12 bg-[#1a1f2e] border-b border-green-900/30 flex items-center justify-between px-4 flex-shrink-0">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-sm text-green-400">apps</span>
          <span className="font-mono text-xs uppercase tracking-wider text-gray-400">
            Application Inventory
          </span>
          {!loading && <span className="text-xs text-gray-600">({apps.length})</span>}
        </div>
        
        <div className="flex items-center gap-2">
          <button
            onClick={loadApps}
            disabled={loading}
            className="p-1.5 hover:bg-green-900/20 rounded transition-colors disabled:opacity-50"
            title="Refresh"
          >
            <span className="material-symbols-outlined text-sm text-gray-400">refresh</span>
          </button>
        </div>
      </div>

      {/* Search & Filters */}
      <div className="p-3 border-b border-green-900/30 space-y-2 flex-shrink-0">
        <input
          type="text"
          placeholder="Search apps..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full px-3 py-2 bg-[#1a1f2e] border border-green-900/30 rounded text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-green-700"
        />
        
        <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
          <input
            type="checkbox"
            checked={showSystemApps}
            onChange={(e) => setShowSystemApps(e.target.checked)}
            className="rounded"
          />
          Show system apps
        </label>
      </div>

      {/* App List */}
      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <div className="w-12 h-12 mx-auto mb-3 border-4 border-green-500/30 border-t-green-500 rounded-full animate-spin"></div>
              <p className="text-xs text-gray-500">Loading applications...</p>
            </div>
          </div>
        ) : filteredApps.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <p className="text-sm text-gray-600">No applications found</p>
          </div>
        ) : (
          <div className="divide-y divide-green-900/30">
            {filteredApps.map((app) => (
              <div
                key={app.package}
                className="p-3 hover:bg-[#1a1f2e] cursor-pointer transition-colors"
                onClick={() => setSelectedApp(app)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-sm text-gray-300 truncate">
                        {app.label || app.package}
                      </span>
                      {app.is_system && (
                        <span className="px-1.5 py-0.5 bg-blue-900/30 text-blue-400 text-[10px] font-mono rounded">
                          SYSTEM
                        </span>
                      )}
                      {!app.enabled && (
                        <span className="px-1.5 py-0.5 bg-gray-900/30 text-gray-500 text-[10px] font-mono rounded">
                          DISABLED
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-600 font-mono truncate">{app.package}</p>
                    <div className="flex items-center gap-3 mt-1">
                      <span className="text-[10px] text-gray-700">v{app.version_name || '?'}</span>
                      {app.permissions && (
                        <span className="text-[10px] text-gray-700">{app.permissions.length} permissions</span>
                      )}
                    </div>
                  </div>
                  
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      pullAPK(app.package)
                    }}
                    className="ml-2 p-1.5 hover:bg-green-900/20 rounded"
                    title="Pull APK"
                  >
                    <span className="material-symbols-outlined text-sm text-green-400">download</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* App Details Modal */}
      {selectedApp && (
        <div 
          className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedApp(null)}
        >
          <div 
            className="bg-[#1a1f2e] rounded-lg border border-green-700 max-w-2xl w-full max-h-[80vh] overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="h-12 bg-[#0f1419] border-b border-green-900/30 flex items-center justify-between px-4">
              <span className="font-mono text-sm text-green-400">{selectedApp.label || selectedApp.package}</span>
              <button
                onClick={() => setSelectedApp(null)}
                className="p-1 hover:bg-green-900/20 rounded"
              >
                <span className="material-symbols-outlined text-base text-gray-400">close</span>
              </button>
            </div>
            
            <div className="p-4 overflow-y-auto max-h-[calc(80vh-3rem)]">
              <div className="space-y-3">
                <div>
                  <div className="text-xs text-gray-600 mb-1">Package</div>
                  <div className="text-sm font-mono text-gray-300">{selectedApp.package}</div>
                </div>
                
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-xs text-gray-600 mb-1">Version</div>
                    <div className="text-sm font-mono text-gray-300">{selectedApp.version_name}</div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-600 mb-1">Version Code</div>
                    <div className="text-sm font-mono text-gray-300">{selectedApp.version_code}</div>
                  </div>
                </div>
                
                <div>
                  <div className="text-xs text-gray-600 mb-1">Installer</div>
                  <div className="text-sm font-mono text-gray-300">{selectedApp.installer || 'Unknown'}</div>
                </div>
                
                {selectedApp.permissions && selectedApp.permissions.length > 0 && (
                  <div>
                    <div className="text-xs text-gray-600 mb-2">Permissions ({selectedApp.permissions.length})</div>
                    <div className="space-y-1 max-h-40 overflow-y-auto">
                      {selectedApp.permissions.map((perm, idx) => (
                        <div key={idx} className="text-xs font-mono text-gray-400 px-2 py-1 bg-[#0f1419] rounded">
                          {perm}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                <div className="flex gap-2 pt-3">
                  <button
                    onClick={() => pullAPK(selectedApp.package)}
                    className="flex-1 px-4 py-2 bg-green-500/20 border border-green-500/50 hover:bg-green-500/30 rounded text-sm font-mono text-green-400 transition-colors"
                  >
                    Pull APK
                  </button>
                  <button
                    onClick={() => setSelectedApp(null)}
                    className="px-4 py-2 bg-[#0f1419] border border-green-900/30 hover:bg-green-900/20 rounded text-sm font-mono text-gray-400 transition-colors"
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default ApplicationInventory
