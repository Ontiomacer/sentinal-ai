/**
 * DEVICE LAB - Dynamic Android Analysis Platform
 * 
 * Real-time Android device integration for dynamic malware analysis
 * Target: Samsung Galaxy A06 (Android 16) via ADB
 * 
 * Architecture Ready for:
 * - ADB device detection
 * - Live screenshot streaming
 * - Runtime log monitoring (logcat)
 * - APK deployment and execution
 * - AI-powered dynamic analysis
 * 
 * Phase 1: Complete UI + Architecture (Frontend Ready)
 * Phase 2: Backend ADB Integration (Python services)
 */

import React, { useState, useEffect } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import DeviceDetectionPanel from '../components/device-lab/DeviceDetectionPanel'
import LiveDeviceScreen from '../components/device-lab/LiveDeviceScreen'
import APKDeploymentPanel from '../components/device-lab/APKDeploymentPanel'
import RuntimeLogStream from '../components/device-lab/RuntimeLogStream'
import RuntimeMonitoringPanel from '../components/device-lab/RuntimeMonitoringPanel'
import AIDynamicAnalyst from '../components/device-lab/AIDynamicAnalyst'
import DynamicInvestigationTimeline from '../components/device-lab/DynamicInvestigationTimeline'
import ApplicationInventory from '../components/device-lab/ApplicationInventory'
import AdvancedRuntimeMonitor from '../components/device-lab/AdvancedRuntimeMonitor'
import SecurityAssessment from '../components/device-lab/SecurityAssessment'

const DeviceLabPage: React.FC = () => {
  const { caseId } = useParams()
  const [searchParams] = useSearchParams()
  const apkParam = searchParams.get('apk')

  const [connectedDevice, setConnectedDevice] = useState<any>(null)
  const [deployedAPK, setDeployedAPK] = useState<string | null>(apkParam)
  const [isRunning, setIsRunning] = useState(false)
  const [runtimeEvents, setRuntimeEvents] = useState<any[]>([])
  const [activePanel, setActivePanel] = useState<'logs' | 'monitoring' | 'ai' | 'advanced' | 'apps' | 'security'>('logs')
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [panelSizes] = useState({
    left: 25, // percentage
    right: 25,
    bottom: 35
  })
  const [collapsedPanels, setCollapsedPanels] = useState({
    left: false,
    right: false,
    bottom: false
  })

  // Real device detection via backend
  useEffect(() => {
    console.log('[DeviceLabPage] Starting device polling')
    
    const pollDevices = async () => {
      console.log('[DeviceLabPage] Polling devices from /api/v1/device-lab/devices')
      
      try {
        const response = await fetch('/api/v1/device-lab/devices')
        console.log('[DeviceLabPage] Device API response status:', response.status, response.ok)
        
        const data = await response.json()
        console.log('[DeviceLabPage] Device API data:', data)
        
        if (data.success && data.devices && data.devices.length > 0) {
          // Use first available device
          const device = data.devices[0]
          console.log('[DeviceLabPage] Device found:', device)
          
          setConnectedDevice({
            model: device.model,
            androidVersion: device.androidVersion,
            serial: device.serial,
            battery: device.battery,
            status: device.status,
            adbReady: device.adbReady
          })
          
          console.log('[DeviceLabPage] Connected device state set')
        } else {
          console.log('[DeviceLabPage] No devices found in response')
          setConnectedDevice(null)
        }
      } catch (error) {
        console.error('[DeviceLabPage] Failed to fetch devices:', error)
      }
    }
    
    // Initial poll
    pollDevices()
    
    // Poll every 3 seconds for device status
    const interval = setInterval(pollDevices, 3000)
    return () => {
      console.log('[DeviceLabPage] Cleanup - stopping device polling')
      clearInterval(interval)
    }
  }, [])

  // Toggle panel collapse
  const togglePanelCollapse = (panel: 'left' | 'right' | 'bottom') => {
    setCollapsedPanels(prev => ({
      ...prev,
      [panel]: !prev[panel]
    }))
  }

  // Simulate runtime events (Backend: WebSocket stream from logcat)
  useEffect(() => {
    if (isRunning && deployedAPK) {
      // TODO Backend: WebSocket connection to /ws/device-lab/logcat
      const interval = setInterval(() => {
        // Mock event for UI demo
        setRuntimeEvents(prev => [...prev, {
          timestamp: new Date(),
          type: 'activity',
          message: 'MainActivity.onCreate() executed',
          severity: 'info'
        }])
      }, 5000)
      return () => clearInterval(interval)
    }
  }, [isRunning, deployedAPK])

  return (
    <div className="h-screen bg-[#0a0a0f] text-gray-200 flex flex-col overflow-hidden">
      {/* Header */}
      <header className="h-16 bg-gradient-to-r from-[#0f1419] via-[#1a1f2e] to-[#0f1419] border-b border-green-900/30 flex items-center px-6 relative z-50">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="w-10 h-10 rounded bg-gradient-to-br from-green-500 to-emerald-600 flex items-center justify-center">
                <span className="material-symbols-outlined text-xl">smartphone</span>
              </div>
              {connectedDevice && (
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
              )}
            </div>
            <div>
              <h1 className="font-mono text-xs uppercase tracking-widest text-green-400">
                Device Lab
              </h1>
              <p className="font-mono text-[10px] text-gray-500 uppercase">
                Dynamic Analysis Platform
              </p>
            </div>
          </div>
        </div>

        <div className="flex-1 flex items-center justify-center">
          {caseId && (
            <div className="text-xs font-mono text-gray-400">
              Case: <span className="text-green-400">{caseId}</span>
            </div>
          )}
          {apkParam && (
            <div className="text-xs font-mono text-gray-400 ml-4">
              APK: <span className="text-green-400">{apkParam}</span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-[#1a1f2e] border border-green-900/30 rounded">
            <div className={`w-2 h-2 rounded-full ${connectedDevice ? 'bg-green-500 animate-pulse' : 'bg-gray-600'}`}></div>
            <span className="text-xs font-mono text-gray-400 uppercase">
              {connectedDevice ? 'Device Connected' : 'No Device'}
            </span>
          </div>

          {isRunning && (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-green-900/20 border border-green-700/50 rounded">
              <span className="material-symbols-outlined text-sm text-green-400 animate-pulse">play_circle</span>
              <span className="text-xs font-mono text-green-400">Running</span>
            </div>
          )}
        </div>
      </header>

      {/* Main Grid - Responsive Layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar - Device Detection & APK Deployment */}
        {!isFullscreen && !collapsedPanels.left && (
          <div 
            className="flex flex-col bg-[#0f1419] border-r border-green-900/30 overflow-hidden transition-all"
            style={{ width: `${panelSizes.left}%` }}
          >
            {/* Left Panel Header */}
            <div className="h-10 bg-[#1a1f2e] border-b border-green-900/30 flex items-center justify-between px-4 flex-shrink-0">
              <span className="font-mono text-xs uppercase tracking-wider text-gray-400">Device Control</span>
              <button
                onClick={() => togglePanelCollapse('left')}
                className="p-1 hover:bg-green-900/20 rounded"
                title="Collapse Panel"
              >
                <span className="material-symbols-outlined text-sm text-gray-400">chevron_left</span>
              </button>
            </div>

            {/* Device Detection */}
            <div className="flex-1 overflow-y-auto">
              <DeviceDetectionPanel 
                device={connectedDevice}
                onDeviceConnect={(device) => setConnectedDevice(device)}
              />
            </div>

            {/* APK Deployment */}
            <div className="flex-1 overflow-y-auto border-t border-green-900/30">
              <APKDeploymentPanel
                device={connectedDevice}
                caseId={caseId}
                preselectedAPK={apkParam}
                onDeploy={(apk) => setDeployedAPK(apk)}
                onLaunch={() => setIsRunning(true)}
                onStop={() => setIsRunning(false)}
              />
            </div>

            {/* Timeline */}
            <div className="h-48 border-t border-green-900/30 overflow-y-auto flex-shrink-0">
              <DynamicInvestigationTimeline events={runtimeEvents} />
            </div>
          </div>
        )}

        {/* Collapsed Left Panel Button */}
        {!isFullscreen && collapsedPanels.left && (
          <div className="w-10 bg-[#1a1f2e] border-r border-green-900/30 flex flex-col items-center py-4 gap-2">
            <button
              onClick={() => togglePanelCollapse('left')}
              className="p-2 hover:bg-green-900/20 rounded"
              title="Show Device Control"
            >
              <span className="material-symbols-outlined text-base text-gray-400">chevron_right</span>
            </button>
            <div className="flex-1"></div>
            <span className="material-symbols-outlined text-base text-gray-600 rotate-90">smartphone</span>
          </div>
        )}

        {/* Center - Device Screen */}
        <div className="flex-1 flex flex-col overflow-hidden min-w-0">
          <LiveDeviceScreen 
            device={connectedDevice}
            isRunning={isRunning}
            isFullscreen={isFullscreen}
            onToggleFullscreen={() => setIsFullscreen(!isFullscreen)}
          />

          {/* Bottom Panel - Logs/Monitoring/AI - Only show when not fullscreen */}
          {!isFullscreen && !collapsedPanels.bottom && (
            <div 
              className="flex flex-col bg-[#0f1419] border-t border-green-900/30 overflow-hidden transition-all"
              style={{ height: `${panelSizes.bottom}%` }}
            >
              {/* Tab Headers */}
              <div className="h-10 flex bg-[#1a1f2e] border-b border-green-900/30 flex-shrink-0">
                <button
                  onClick={() => setActivePanel('logs')}
                  className={`px-4 py-2 text-xs font-mono uppercase transition-colors flex items-center gap-2 ${
                    activePanel === 'logs'
                      ? 'bg-[#0f1419] text-green-400 border-b-2 border-green-500'
                      : 'text-gray-500 hover:text-gray-300'
                  }`}
                >
                  <span className="material-symbols-outlined text-sm">terminal</span>
                  Logs
                </button>
                <button
                  onClick={() => setActivePanel('monitoring')}
                  className={`px-4 py-2 text-xs font-mono uppercase transition-colors flex items-center gap-2 ${
                    activePanel === 'monitoring'
                      ? 'bg-[#0f1419] text-green-400 border-b-2 border-green-500'
                      : 'text-gray-500 hover:text-gray-300'
                  }`}
                >
                  <span className="material-symbols-outlined text-sm">monitoring</span>
                  Monitoring
                </button>
                <button
                  onClick={() => setActivePanel('advanced')}
                  className={`px-4 py-2 text-xs font-mono uppercase transition-colors flex items-center gap-2 ${
                    activePanel === 'advanced'
                      ? 'bg-[#0f1419] text-green-400 border-b-2 border-green-500'
                      : 'text-gray-500 hover:text-gray-300'
                  }`}
                >
                  <span className="material-symbols-outlined text-sm">security</span>
                  Advanced
                </button>
                <button
                  onClick={() => setActivePanel('ai')}
                  className={`px-4 py-2 text-xs font-mono uppercase transition-colors flex items-center gap-2 ${
                    activePanel === 'ai'
                      ? 'bg-[#0f1419] text-green-400 border-b-2 border-green-500'
                      : 'text-gray-500 hover:text-gray-300'
                  }`}
                >
                  <span className="material-symbols-outlined text-sm">psychology</span>
                  AI
                </button>
                <button
                  onClick={() => setActivePanel('apps')}
                  className={`px-4 py-2 text-xs font-mono uppercase transition-colors flex items-center gap-2 ${
                    activePanel === 'apps'
                      ? 'bg-[#0f1419] text-green-400 border-b-2 border-green-500'
                      : 'text-gray-500 hover:text-gray-300'
                  }`}
                >
                  <span className="material-symbols-outlined text-sm">apps</span>
                  Apps
                </button>
                <button
                  onClick={() => setActivePanel('security')}
                  className={`px-4 py-2 text-xs font-mono uppercase transition-colors flex items-center gap-2 ${
                    activePanel === 'security'
                      ? 'bg-[#0f1419] text-green-400 border-b-2 border-green-500'
                      : 'text-gray-500 hover:text-gray-300'
                  }`}
                >
                  <span className="material-symbols-outlined text-sm">shield</span>
                  Security
                </button>
                
                <div className="flex-1"></div>
                
                <button
                  onClick={() => togglePanelCollapse('bottom')}
                  className="px-3 hover:bg-green-900/20"
                  title="Collapse Panel"
                >
                  <span className="material-symbols-outlined text-sm text-gray-400">expand_more</span>
                </button>
              </div>

              {/* Tab Content */}
              <div className="flex-1 overflow-hidden">
                {activePanel === 'logs' && <RuntimeLogStream device={connectedDevice} isRunning={isRunning} />}
                {activePanel === 'monitoring' && <RuntimeMonitoringPanel device={connectedDevice} isRunning={isRunning} />}
                {activePanel === 'advanced' && <AdvancedRuntimeMonitor device={connectedDevice} package={deployedAPK || undefined} />}
                {activePanel === 'ai' && <AIDynamicAnalyst events={runtimeEvents} deployedAPK={deployedAPK} />}
                {activePanel === 'apps' && <ApplicationInventory device={connectedDevice} />}
                {activePanel === 'security' && <SecurityAssessment device={connectedDevice} />}
              </div>
            </div>
          )}

          {/* Collapsed Bottom Panel Button */}
          {!isFullscreen && collapsedPanels.bottom && (
            <div className="h-10 bg-[#1a1f2e] border-t border-green-900/30 flex items-center justify-between px-4">
              <div className="flex items-center gap-4">
                <span className="text-xs font-mono text-gray-500 uppercase">Analysis Panels</span>
                <div className="flex gap-2">
                  <span className={`text-xs font-mono ${activePanel === 'logs' ? 'text-green-400' : 'text-gray-600'}`}>Logs</span>
                  <span className="text-gray-700">•</span>
                  <span className={`text-xs font-mono ${activePanel === 'monitoring' ? 'text-green-400' : 'text-gray-600'}`}>Monitoring</span>
                  <span className="text-gray-700">•</span>
                  <span className={`text-xs font-mono ${activePanel === 'advanced' ? 'text-green-400' : 'text-gray-600'}`}>Advanced</span>
                  <span className="text-gray-700">•</span>
                  <span className={`text-xs font-mono ${activePanel === 'ai' ? 'text-green-400' : 'text-gray-600'}`}>AI</span>
                  <span className="text-gray-700">•</span>
                  <span className={`text-xs font-mono ${activePanel === 'apps' ? 'text-green-400' : 'text-gray-600'}`}>Apps</span>
                  <span className="text-gray-700">•</span>
                  <span className={`text-xs font-mono ${activePanel === 'security' ? 'text-green-400' : 'text-gray-600'}`}>Security</span>
                </div>
              </div>
              <button
                onClick={() => togglePanelCollapse('bottom')}
                className="p-1 hover:bg-green-900/20 rounded"
                title="Show Runtime Analysis"
              >
                <span className="material-symbols-outlined text-sm text-gray-400">expand_less</span>
              </button>
            </div>
          )}
        </div>

        {/* Right Sidebar - Integration (hidden in fullscreen) */}
        {!isFullscreen && !collapsedPanels.right && (
          <div 
            className="flex flex-col bg-[#0f1419] border-l border-green-900/30 overflow-hidden transition-all"
            style={{ width: `${panelSizes.right}%` }}
          >
            <div className="h-10 bg-[#1a1f2e] border-b border-green-900/30 flex items-center justify-between px-4 flex-shrink-0">
              <span className="font-mono text-xs uppercase tracking-wider text-gray-400">Integration</span>
              <button
                onClick={() => togglePanelCollapse('right')}
                className="p-1 hover:bg-green-900/20 rounded"
                title="Collapse Panel"
              >
                <span className="material-symbols-outlined text-sm text-gray-400">chevron_right</span>
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {/* Backend Status */}
              <div className="p-3 bg-green-900/10 border border-green-700/30 rounded">
                <div className="flex items-center gap-2 mb-2">
                  <span className="material-symbols-outlined text-sm text-green-400">check_circle</span>
                  <span className="text-xs font-mono text-green-400 uppercase">System Ready</span>
                </div>
                <p className="text-xs text-gray-400 leading-relaxed">
                  Device Lab V3 - Interactive Mirroring Active
                </p>
              </div>

              {/* Quick Actions */}
              <div>
                <div className="text-[10px] font-mono text-gray-600 uppercase mb-2">Quick Actions</div>
                <div className="space-y-2">
                  <button
                    onClick={() => setIsFullscreen(true)}
                    disabled={!connectedDevice}
                    className="w-full px-3 py-2 bg-green-500/20 border border-green-500/50 hover:bg-green-500/30 disabled:opacity-50 disabled:cursor-not-allowed rounded text-sm font-mono text-green-400 transition-colors flex items-center gap-2"
                  >
                    <span className="material-symbols-outlined text-sm">fullscreen</span>
                    Enter Fullscreen
                  </button>
                  
                  <button
                    onClick={() => setCollapsedPanels({ left: false, right: false, bottom: false })}
                    className="w-full px-3 py-2 bg-[#1a1f2e] border border-green-900/30 hover:bg-green-900/20 rounded text-sm font-mono text-gray-400 transition-colors flex items-center gap-2"
                  >
                    <span className="material-symbols-outlined text-sm">open_in_full</span>
                    Restore All Panels
                  </button>
                </div>
              </div>

              {/* Keyboard Shortcuts */}
              <div>
                <div className="text-[10px] font-mono text-gray-600 uppercase mb-2">Keyboard Shortcuts</div>
                <div className="space-y-1 text-xs font-mono text-gray-500">
                  <div className="flex justify-between">
                    <span>Fullscreen</span>
                    <span className="text-gray-600">F11</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Exit Fullscreen</span>
                    <span className="text-gray-600">ESC</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Rotate Device</span>
                    <span className="text-gray-600">Ctrl+R</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Screenshot</span>
                    <span className="text-gray-600">Ctrl+S</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Collapsed Right Panel Button */}
        {!isFullscreen && collapsedPanels.right && (
          <div className="w-10 bg-[#1a1f2e] border-l border-green-900/30 flex flex-col items-center py-4 gap-2">
            <button
              onClick={() => togglePanelCollapse('right')}
              className="p-2 hover:bg-green-900/20 rounded"
              title="Show Integration"
            >
              <span className="material-symbols-outlined text-base text-gray-400">chevron_left</span>
            </button>
            <div className="flex-1"></div>
            <span className="material-symbols-outlined text-base text-gray-600 rotate-90">integration_instructions</span>
          </div>
        )}
      </div>
    </div>
  )
}

export default DeviceLabPage
