/**
 * ACTIVE APPLICATION INTELLIGENCE PANEL
 * Displays the currently running foreground application with context
 */

import React, { useState, useEffect, useRef } from 'react';
import { Activity, Package, Shield, Info } from 'lucide-react';

interface Props {
  deviceSerial?: string;
  onAnalyze?: (packageName: string) => void;
}

interface ActiveApp {
  name: string;
  package: string;
  category: string;
  description: string;
  publisher: string;
  version?: string;
  permissions: string[];
  components: number;
  lastUpdated?: string;
}

const ActiveApplicationPanel: React.FC<Props> = ({ deviceSerial, onAnalyze }) => {
  const [activeApp, setActiveApp] = useState<ActiveApp | null>(null);
  const requestInFlightRef = useRef(false);

  useEffect(() => {
    if (!deviceSerial) {
      setActiveApp(null);
      return;
    }

    const pollActiveApp = async () => {
      if (requestInFlightRef.current || document.hidden) {
        return;
      }
      requestInFlightRef.current = true;
      try {
        const response = await fetch(`/api/v1/device-lab/runtime/foreground-app?serial=${deviceSerial}`);
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.app) {
            setActiveApp(data.app);
          }
        }
      } catch (error) {
        console.error('[ActiveApplicationPanel] Failed to fetch foreground app:', error);
      } finally {
        requestInFlightRef.current = false;
      }
    };

    // Poll every 2 seconds
    pollActiveApp();
    const interval = setInterval(pollActiveApp, 2000);

    return () => clearInterval(interval);
  }, [deviceSerial]);

  if (!deviceSerial) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center text-gray-500">
          <Activity className="w-12 h-12 mx-auto mb-2 opacity-30" />
          <p className="text-sm">No device connected</p>
        </div>
      </div>
    );
  }

  if (!activeApp) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-500 mx-auto mb-2"></div>
          <p className="text-sm text-gray-400">Detecting active app...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-gray-900">
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-800 bg-gray-800/50">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-green-500" />
          <h3 className="text-sm font-semibold text-white">Active Application</h3>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* App Identity */}
        <div className="bg-gray-800 rounded-lg p-4 space-y-3">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <h4 className="text-lg font-semibold text-white mb-1">{activeApp.name}</h4>
              <p className="text-xs font-mono text-gray-400">{activeApp.package}</p>
            </div>
            <div className="flex items-center gap-1 px-2 py-1 bg-green-900/30 rounded text-xs text-green-400 border border-green-700/30">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              ACTIVE
            </div>
          </div>

          {activeApp.description && (
            <p className="text-sm text-gray-300 leading-relaxed">
              {activeApp.description}
            </p>
          )}

          <div className="grid grid-cols-2 gap-3 pt-2 border-t border-gray-700">
            <div>
              <p className="text-xs text-gray-500 mb-1">Category</p>
              <p className="text-sm text-gray-300">{activeApp.category}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500 mb-1">Publisher</p>
              <p className="text-sm text-gray-300">{activeApp.publisher}</p>
            </div>
          </div>

          {activeApp.version && (
            <div className="pt-2 border-t border-gray-700">
              <p className="text-xs text-gray-500 mb-1">Version</p>
              <p className="text-sm font-mono text-gray-300">{activeApp.version}</p>
            </div>
          )}

          {activeApp.lastUpdated && (
            <div className="pt-2 border-t border-gray-700">
              <p className="text-xs text-gray-500 mb-1">Last Updated</p>
              <p className="text-sm text-gray-300">{activeApp.lastUpdated}</p>
            </div>
          )}
        </div>

        {/* Runtime Stats */}
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-gray-800 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-2">
              <Package className="w-4 h-4 text-blue-400" />
              <p className="text-xs text-gray-400">Components</p>
            </div>
            <p className="text-2xl font-bold text-white">{activeApp.components}</p>
          </div>

          <div className="bg-gray-800 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-4 h-4 text-yellow-400" />
              <p className="text-xs text-gray-400">Permissions</p>
            </div>
            <p className="text-2xl font-bold text-white">{activeApp.permissions.length}</p>
          </div>
        </div>

        {/* Key Permissions */}
        {activeApp.permissions.length > 0 && (
          <div className="bg-gray-800 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3">
              <Shield className="w-4 h-4 text-yellow-400" />
              <h4 className="text-sm font-semibold text-white">Key Permissions</h4>
            </div>
            <div className="space-y-2">
              {activeApp.permissions.slice(0, 5).map((perm, idx) => (
                <div key={idx} className="flex items-center gap-2 text-sm">
                  <div className="w-1.5 h-1.5 bg-yellow-500 rounded-full"></div>
                  <span className="text-gray-300">{perm}</span>
                </div>
              ))}
              {activeApp.permissions.length > 5 && (
                <p className="text-xs text-gray-500 mt-2">
                  +{activeApp.permissions.length - 5} more permissions
                </p>
              )}
            </div>
          </div>
        )}

        {/* Analyze Button */}
        {onAnalyze && (
          <button
            onClick={() => onAnalyze(activeApp.package)}
            className="w-full py-3 bg-green-600 hover:bg-green-700 text-white rounded-lg font-semibold transition-colors flex items-center justify-center gap-2"
          >
            <Info className="w-4 h-4" />
            Analyze Application
          </button>
        )}
      </div>
    </div>
  );
};

export default ActiveApplicationPanel;
