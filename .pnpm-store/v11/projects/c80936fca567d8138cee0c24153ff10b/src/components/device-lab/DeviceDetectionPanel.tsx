/**
 * DEVICE DETECTION PANEL
 * Displays connected Android device information
 * Backend Integration: GET /api/v1/device-lab/devices
 */

import React from 'react'

interface Device {
  model: string
  androidVersion: string
  serial: string
  battery: number
  status: 'connected' | 'disconnected' | 'unauthorized'
  adbReady: boolean
}

interface Props {
  device: Device | null
  onDeviceConnect: (device: Device) => void
}

const DeviceDetectionPanel: React.FC<Props> = ({ device }) => {
  return (
    <div className="h-full bg-[#0f1419] border border-green-900/30 rounded flex flex-col overflow-hidden">
      <div className="h-10 bg-[#1a1f2e] border-b border-green-900/30 flex items-center px-4">
        <span className="material-symbols-outlined text-sm text-green-400 mr-2">devices</span>
        <span className="font-mono text-xs uppercase tracking-wider text-gray-400">
          Device Detection
        </span>
      </div>

      <div className="flex-1 p-4">
        {device ? (
          <div className="space-y-3">
            {/* Device Model */}
            <div className="p-3 bg-green-900/10 border border-green-700/30 rounded">
              <div className="flex items-center gap-3">
                <span className="material-symbols-outlined text-2xl text-green-400">smartphone</span>
                <div>
                  <div className="text-sm font-medium text-white">{device.model}</div>
                  <div className="text-xs text-gray-500 font-mono">Android {device.androidVersion}</div>
                </div>
              </div>
            </div>

            {/* Device Info Grid */}
            <div className="grid grid-cols-2 gap-2">
              <div className="p-2 bg-[#1a1f2e] rounded border border-green-900/30">
                <div className="text-[10px] font-mono text-gray-600 uppercase mb-1">Serial</div>
                <div className="text-xs font-mono text-gray-300">{device.serial}</div>
              </div>

              <div className="p-2 bg-[#1a1f2e] rounded border border-green-900/30">
                <div className="text-[10px] font-mono text-gray-600 uppercase mb-1">Battery</div>
                <div className="text-xs font-mono text-green-400">{device.battery}%</div>
              </div>

              <div className="p-2 bg-[#1a1f2e] rounded border border-green-900/30">
                <div className="text-[10px] font-mono text-gray-600 uppercase mb-1">Status</div>
                <div className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500"></span>
                  <span className="text-xs font-mono text-green-400">Connected</span>
                </div>
              </div>

              <div className="p-2 bg-[#1a1f2e] rounded border border-green-900/30">
                <div className="text-[10px] font-mono text-gray-600 uppercase mb-1">ADB</div>
                <div className="flex items-center gap-1">
                  <span className="material-symbols-outlined text-xs text-green-400">check_circle</span>
                  <span className="text-xs font-mono text-green-400">Ready</span>
                </div>
              </div>
            </div>

            {/* Connection Details */}
            <div className="p-2 bg-[#1a1f2e] rounded border border-green-900/30 text-xs font-mono text-gray-500">
              <div>ADB Version: 1.0.41</div>
              <div>Connection: USB</div>
              <div>Last Ping: {new Date().toLocaleTimeString()}</div>
            </div>
          </div>
        ) : (
          <div className="h-full flex items-center justify-center">
            <div className="text-center">
              <div className="w-16 h-16 mx-auto mb-4 relative">
                <div className="absolute inset-0 border-4 border-gray-700 rounded-full"></div>
                <span className="material-symbols-outlined text-3xl text-gray-600 absolute inset-0 m-auto">
                  smartphone
                </span>
              </div>
              <p className="text-xs font-mono text-gray-600 mb-2">No Device Connected</p>
              <p className="text-[10px] font-mono text-gray-700">
                Connect via ADB
              </p>
              <div className="mt-4">
                <button className="px-3 py-1 bg-[#1a1f2e] border border-green-900/30 hover:border-green-700 rounded text-xs font-mono text-gray-400 hover:text-green-400 transition-colors">
                  <span className="material-symbols-outlined text-sm mr-1 align-middle">refresh</span>
                  Scan for Devices
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default DeviceDetectionPanel
