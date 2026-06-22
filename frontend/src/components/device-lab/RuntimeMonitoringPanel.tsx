/**
 * RUNTIME MONITORING PANEL
 * Monitor Activities, Services, Receivers, and Permissions at runtime
 * Backend Integration: GET /api/v1/device-lab/runtime-info
 */

import React, { useState, useEffect } from 'react'

interface Props {
  device: any
  isRunning: boolean
}

interface RuntimeInfo {
  activities: Activity[]
  services: Service[]
  receivers: Receiver[]
  permissions: Permission[]
}

interface Activity {
  name: string
  state: 'running' | 'paused' | 'stopped'
  timestamp: string
}

interface Service {
  name: string
  pid: number
  startTime: string
}

interface Receiver {
  name: string
  action: string
  timestamp: string
}

interface Permission {
  name: string
  granted: boolean
  timestamp: string
}

const RuntimeMonitoringPanel: React.FC<Props> = ({ device, isRunning }) => {
  const [runtimeInfo, setRuntimeInfo] = useState<RuntimeInfo>({
    activities: [],
    services: [],
    receivers: [],
    permissions: []
  })
  const [activeTab, setActiveTab] = useState<'activities' | 'services' | 'receivers' | 'permissions'>('activities')

  // Real runtime information polling
  useEffect(() => {
    if (!device || !isRunning) return

    const fetchRuntimeInfo = async () => {
      try {
        const response = await fetch(`/api/v1/device-lab/runtime-info?serial=${device.serial}`)
        const data = await response.json()

        if (data.success && data.runtime_info) {
          setRuntimeInfo(data.runtime_info)
        }
      } catch (error) {
        console.error('Failed to fetch runtime info:', error)
      }
    }

    // Initial fetch
    fetchRuntimeInfo()

    // Poll every 5 seconds
    const interval = setInterval(fetchRuntimeInfo, 5000)

    return () => clearInterval(interval)
  }, [device, isRunning])

  const getStateColor = (state: string) => {
    switch (state) {
      case 'running': return 'text-green-400'
      case 'paused': return 'text-yellow-400'
      case 'stopped': return 'text-gray-600'
      default: return 'text-gray-500'
    }
  }

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString()
  }

  return (
    <div className="h-full bg-[#0f1419] border border-green-900/30 rounded flex flex-col overflow-hidden">
      {/* Tab Headers */}
      <div className="h-10 bg-[#1a1f2e] border-b border-green-900/30 flex items-center">
        <button
          onClick={() => setActiveTab('activities')}
          className={`flex-1 h-full px-3 text-xs font-mono uppercase transition-colors ${
            activeTab === 'activities'
              ? 'bg-[#0f1419] text-green-400 border-b-2 border-green-500'
              : 'text-gray-500 hover:text-gray-300'
          }`}
        >
          Activities ({runtimeInfo.activities.length})
        </button>
        <button
          onClick={() => setActiveTab('services')}
          className={`flex-1 h-full px-3 text-xs font-mono uppercase transition-colors ${
            activeTab === 'services'
              ? 'bg-[#0f1419] text-green-400 border-b-2 border-green-500'
              : 'text-gray-500 hover:text-gray-300'
          }`}
        >
          Services ({runtimeInfo.services.length})
        </button>
        <button
          onClick={() => setActiveTab('receivers')}
          className={`flex-1 h-full px-3 text-xs font-mono uppercase transition-colors ${
            activeTab === 'receivers'
              ? 'bg-[#0f1419] text-green-400 border-b-2 border-green-500'
              : 'text-gray-500 hover:text-gray-300'
          }`}
        >
          Receivers ({runtimeInfo.receivers.length})
        </button>
        <button
          onClick={() => setActiveTab('permissions')}
          className={`flex-1 h-full px-3 text-xs font-mono uppercase transition-colors ${
            activeTab === 'permissions'
              ? 'bg-[#0f1419] text-green-400 border-b-2 border-green-500'
              : 'text-gray-500 hover:text-gray-300'
          }`}
        >
          Permissions ({runtimeInfo.permissions.length})
        </button>
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-y-auto">
        {!device || !isRunning ? (
          <div className="h-full flex items-center justify-center">
            <div className="text-center">
              <span className="material-symbols-outlined text-3xl text-gray-700 mb-2 block">
                monitoring
              </span>
              <p className="text-xs font-mono text-gray-600">
                {!device ? 'No device connected' : 'Launch APK to start monitoring'}
              </p>
            </div>
          </div>
        ) : (
          <>
            {/* Activities Tab */}
            {activeTab === 'activities' && (
              <div className="p-3 space-y-2">
                {runtimeInfo.activities.map((activity, idx) => (
                  <div key={idx} className="p-3 bg-[#1a1f2e] border border-green-900/30 rounded hover:border-green-700 transition-colors">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-white">{activity.name}</span>
                      <span className={`text-[10px] font-mono uppercase ${getStateColor(activity.state)}`}>
                        {activity.state}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-[10px] font-mono text-gray-600">
                      <span className="material-symbols-outlined text-xs">schedule</span>
                      {formatTimestamp(activity.timestamp)}
                    </div>
                  </div>
                ))}
                {runtimeInfo.activities.length === 0 && (
                  <div className="text-center py-8 text-xs font-mono text-gray-600">
                    No activities detected
                  </div>
                )}
              </div>
            )}

            {/* Services Tab */}
            {activeTab === 'services' && (
              <div className="p-3 space-y-2">
                {runtimeInfo.services.map((service, idx) => (
                  <div key={idx} className="p-3 bg-[#1a1f2e] border border-green-900/30 rounded hover:border-green-700 transition-colors">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-white">{service.name}</span>
                      <span className="px-2 py-0.5 bg-green-900/30 rounded text-[10px] font-mono text-green-400">
                        PID: {service.pid}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-[10px] font-mono text-gray-600">
                      <span className="material-symbols-outlined text-xs">schedule</span>
                      Started: {formatTimestamp(service.startTime)}
                    </div>
                  </div>
                ))}
                {runtimeInfo.services.length === 0 && (
                  <div className="text-center py-8 text-xs font-mono text-gray-600">
                    No services running
                  </div>
                )}
              </div>
            )}

            {/* Receivers Tab */}
            {activeTab === 'receivers' && (
              <div className="p-3 space-y-2">
                {runtimeInfo.receivers.map((receiver, idx) => (
                  <div key={idx} className="p-3 bg-[#1a1f2e] border border-green-900/30 rounded hover:border-green-700 transition-colors">
                    <div className="text-xs font-mono text-white mb-1">{receiver.name}</div>
                    <div className="text-[10px] font-mono text-cyan-400 mb-2">{receiver.action}</div>
                    <div className="flex items-center gap-2 text-[10px] font-mono text-gray-600">
                      <span className="material-symbols-outlined text-xs">schedule</span>
                      {formatTimestamp(receiver.timestamp)}
                    </div>
                  </div>
                ))}
                {runtimeInfo.receivers.length === 0 && (
                  <div className="text-center py-8 text-xs font-mono text-gray-600">
                    No receivers registered
                  </div>
                )}
              </div>
            )}

            {/* Permissions Tab */}
            {activeTab === 'permissions' && (
              <div className="p-3 space-y-2">
                {runtimeInfo.permissions.map((permission, idx) => (
                  <div key={idx} className="p-3 bg-[#1a1f2e] border border-green-900/30 rounded hover:border-green-700 transition-colors">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono text-white">{permission.name}</span>
                      <div className="flex items-center gap-1">
                        <span className={`material-symbols-outlined text-sm ${
                          permission.granted ? 'text-green-400' : 'text-red-400'
                        }`}>
                          {permission.granted ? 'check_circle' : 'cancel'}
                        </span>
                        <span className={`text-[10px] font-mono uppercase ${
                          permission.granted ? 'text-green-400' : 'text-red-400'
                        }`}>
                          {permission.granted ? 'Granted' : 'Denied'}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 text-[10px] font-mono text-gray-600">
                      <span className="material-symbols-outlined text-xs">schedule</span>
                      {formatTimestamp(permission.timestamp)}
                    </div>
                  </div>
                ))}
                {runtimeInfo.permissions.length === 0 && (
                  <div className="text-center py-8 text-xs font-mono text-gray-600">
                    No permissions requested
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>

      {/* Status Bar */}
      {device && isRunning && (
        <div className="h-8 bg-[#1a1f2e] border-t border-green-900/30 flex items-center justify-between px-4">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
            <span className="text-[10px] font-mono text-green-400">
              Monitoring runtime
            </span>
          </div>
          <div className="text-[10px] font-mono text-gray-600">
            Backend: adb shell dumpsys activity
          </div>
        </div>
      )}
    </div>
  )
}

export default RuntimeMonitoringPanel
