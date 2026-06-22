/**
 * APK DEPLOYMENT PANEL
 * Deploy, launch, and control APKs on connected device
 * Backend Integration: 
 * - POST /api/v1/device-lab/install
 * - POST /api/v1/device-lab/launch
 * - POST /api/v1/device-lab/stop
 */

import React, { useState, useEffect } from 'react'

interface Props {
  device: any
  caseId?: string
  preselectedAPK?: string | null
  onDeploy: (apk: string) => void
  onLaunch: () => void
  onStop: () => void
}

interface APK {
  id: string
  name: string
  package_name: string
  version: string
  size: number
  uploaded_at: string
}

const APKDeploymentPanel: React.FC<Props> = ({ 
  device, 
  caseId, 
  preselectedAPK,
  onDeploy,
  onLaunch,
  onStop 
}) => {
  const [availableAPKs, setAvailableAPKs] = useState<APK[]>([])
  const [selectedAPK, setSelectedAPK] = useState<string | null>(preselectedAPK ?? null)
  const [isInstalled, setIsInstalled] = useState(false)
  const [isRunning, setIsRunning] = useState(false)
  const [deploymentStatus, setDeploymentStatus] = useState<'idle' | 'installing' | 'success' | 'error'>('idle')
  const [statusMessage, setStatusMessage] = useState('')

  useEffect(() => {
    setAvailableAPKs([])
  }, [caseId])

  // Preselect APK if provided
  useEffect(() => {
    if (preselectedAPK) {
      setSelectedAPK(preselectedAPK)
    }
  }, [preselectedAPK])

  const handleInstall = async () => {
    if (!device || !selectedAPK) return

    setDeploymentStatus('installing')
    setStatusMessage('Installing APK...')

    try {
      const response = await fetch('/api/v1/device-lab/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_serial: device.serial,
          apk_path: selectedAPK,
          replace: true
        })
      })

      const data = await response.json()

      if (data.success) {
        setDeploymentStatus('success')
        setStatusMessage('Installation successful')
        setIsInstalled(true)
        onDeploy(selectedAPK)
        
        setTimeout(() => {
          setDeploymentStatus('idle')
          setStatusMessage('')
        }, 2000)
      } else {
        setDeploymentStatus('error')
        setStatusMessage(data.message || 'Installation failed')
        setTimeout(() => {
          setDeploymentStatus('idle')
        }, 3000)
      }
    } catch (error) {
      console.error('Installation error:', error)
      setDeploymentStatus('error')
      setStatusMessage('Installation failed: ' + error)
      setTimeout(() => {
        setDeploymentStatus('idle')
      }, 3000)
    }
  }

  const handleLaunch = async () => {
    if (!device || !isInstalled) return
    
    try {
      const selectedAPKObj = availableAPKs.find(apk => apk.name === selectedAPK)
      if (!selectedAPKObj) return

      const response = await fetch('/api/v1/device-lab/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_serial: device.serial,
          package_name: selectedAPKObj.package_name
        })
      })

      const data = await response.json()

      if (data.success) {
        setIsRunning(true)
        onLaunch()
      } else {
        setStatusMessage('Launch failed: ' + data.message)
        setTimeout(() => setStatusMessage(''), 3000)
      }
    } catch (error) {
      console.error('Launch error:', error)
      setStatusMessage('Launch failed')
      setTimeout(() => setStatusMessage(''), 3000)
    }
  }

  const handleStop = async () => {
    if (!device || !isRunning) return
    
    try {
      const selectedAPKObj = availableAPKs.find(apk => apk.name === selectedAPK)
      if (!selectedAPKObj) return

      const response = await fetch('/api/v1/device-lab/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_serial: device.serial,
          package_name: selectedAPKObj.package_name
        })
      })

      const data = await response.json()

      if (data.success) {
        setIsRunning(false)
        onStop()
      }
    } catch (error) {
      console.error('Stop error:', error)
    }
  }

  const handleUninstall = async () => {
    if (!device || !isInstalled) return
    
    try {
      const selectedAPKObj = availableAPKs.find(apk => apk.name === selectedAPK)
      if (!selectedAPKObj) return

      const response = await fetch('/api/v1/device-lab/uninstall', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_serial: device.serial,
          package_name: selectedAPKObj.package_name
        })
      })

      const data = await response.json()

      if (data.success) {
        setIsInstalled(false)
        setIsRunning(false)
        setStatusMessage('Uninstalled successfully')
        setTimeout(() => setStatusMessage(''), 2000)
      }
    } catch (error) {
      console.error('Uninstall error:', error)
      setStatusMessage('Uninstall failed')
      setTimeout(() => setStatusMessage(''), 3000)
    }
  }

  const formatSize = (bytes: number) => {
    return (bytes / 1024 / 1024).toFixed(2) + ' MB'
  }

  return (
    <div className="h-full bg-[#0f1419] border border-green-900/30 rounded flex flex-col overflow-hidden">
      <div className="h-10 bg-[#1a1f2e] border-b border-green-900/30 flex items-center px-4">
        <span className="material-symbols-outlined text-sm text-green-400 mr-2">deployed_code</span>
        <span className="font-mono text-xs uppercase tracking-wider text-gray-400">
          APK Deployment
        </span>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {!device ? (
          <div className="h-full flex items-center justify-center">
            <div className="text-center">
              <span className="material-symbols-outlined text-3xl text-gray-700 mb-2 block">
                warning
              </span>
              <p className="text-xs font-mono text-gray-600">No device connected</p>
            </div>
          </div>
        ) : (
          <>
            {/* APK Selection */}
            <div>
              <div className="text-[10px] font-mono text-gray-600 uppercase mb-2">Select APK</div>
              <div className="space-y-2 max-h-32 overflow-y-auto">
                {availableAPKs.map((apk) => (
                  <button
                    key={apk.id}
                    onClick={() => setSelectedAPK(apk.name)}
                    className={`w-full p-2 text-left rounded border transition-colors ${
                      selectedAPK === apk.name
                        ? 'bg-green-900/20 border-green-700 text-green-400'
                        : 'bg-[#1a1f2e] border-green-900/30 text-gray-400 hover:border-green-700'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-mono truncate">{apk.name}</div>
                        <div className="text-[10px] font-mono text-gray-600 truncate mt-0.5">
                          {apk.package_name}
                        </div>
                      </div>
                      <div className="text-[10px] font-mono text-gray-600 ml-2">
                        {formatSize(apk.size)}
                      </div>
                    </div>
                  </button>
                ))}
              </div>
              {availableAPKs.length === 0 && (
                <div className="text-xs font-mono text-gray-600 text-center py-4">
                  No APKs in this case
                </div>
              )}
            </div>

            {/* Selected APK Info */}
            {selectedAPK && (
              <div className="p-3 bg-[#1a1f2e] border border-green-900/30 rounded">
                <div className="text-[10px] font-mono text-gray-600 uppercase mb-2">Selected</div>
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-sm text-green-400">android</span>
                  <span className="text-xs font-mono text-white">{selectedAPK}</span>
                </div>
                {isInstalled && (
                  <div className="flex items-center gap-1 mt-2">
                    <span className="material-symbols-outlined text-xs text-green-400">check_circle</span>
                    <span className="text-[10px] font-mono text-green-400">Installed</span>
                  </div>
                )}
              </div>
            )}

            {/* Deployment Status */}
            {statusMessage && (
              <div className={`p-2 rounded border text-xs font-mono ${
                deploymentStatus === 'success' 
                  ? 'bg-green-900/20 border-green-700 text-green-400'
                  : deploymentStatus === 'error'
                  ? 'bg-red-900/20 border-red-700 text-red-400'
                  : 'bg-yellow-900/20 border-yellow-700 text-yellow-400'
              }`}>
                {statusMessage}
              </div>
            )}

            {/* Action Buttons */}
            <div className="space-y-2">
              {/* Install */}
              <button
                onClick={handleInstall}
                disabled={!selectedAPK || isInstalled || deploymentStatus === 'installing'}
                className="w-full px-3 py-2 bg-green-500/20 border border-green-500/50 hover:bg-green-500/30 disabled:opacity-50 disabled:cursor-not-allowed rounded text-sm font-mono text-green-400 transition-colors flex items-center justify-center gap-2"
              >
                {deploymentStatus === 'installing' ? (
                  <>
                    <span className="material-symbols-outlined text-sm animate-spin">progress_activity</span>
                    Installing...
                  </>
                ) : (
                  <>
                    <span className="material-symbols-outlined text-sm">download</span>
                    Install APK
                  </>
                )}
              </button>

              {/* Launch */}
              <button
                onClick={handleLaunch}
                disabled={!isInstalled || isRunning}
                className="w-full px-3 py-2 bg-blue-500/20 border border-blue-500/50 hover:bg-blue-500/30 disabled:opacity-50 disabled:cursor-not-allowed rounded text-sm font-mono text-blue-400 transition-colors flex items-center justify-center gap-2"
              >
                <span className="material-symbols-outlined text-sm">play_circle</span>
                Launch
              </button>

              {/* Stop */}
              <button
                onClick={handleStop}
                disabled={!isRunning}
                className="w-full px-3 py-2 bg-orange-500/20 border border-orange-500/50 hover:bg-orange-500/30 disabled:opacity-50 disabled:cursor-not-allowed rounded text-sm font-mono text-orange-400 transition-colors flex items-center justify-center gap-2"
              >
                <span className="material-symbols-outlined text-sm">stop_circle</span>
                Stop
              </button>

              {/* Uninstall */}
              <button
                onClick={handleUninstall}
                disabled={!isInstalled || isRunning}
                className="w-full px-3 py-2 bg-red-500/20 border border-red-500/50 hover:bg-red-500/30 disabled:opacity-50 disabled:cursor-not-allowed rounded text-sm font-mono text-red-400 transition-colors flex items-center justify-center gap-2"
              >
                <span className="material-symbols-outlined text-sm">delete</span>
                Uninstall
              </button>
            </div>

            {/* Backend Command Info */}
            <div className="p-2 bg-[#1a1f2e] rounded border border-green-900/30 text-[10px] font-mono text-gray-600">
              <div className="mb-1 text-gray-500">Backend Commands:</div>
              <div>adb install &lt;apk&gt;</div>
              <div>adb shell monkey -p &lt;pkg&gt; 1</div>
              <div>adb shell am force-stop &lt;pkg&gt;</div>
              <div>adb uninstall &lt;pkg&gt;</div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

export default APKDeploymentPanel
