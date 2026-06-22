import React, { useEffect, useRef, useState } from 'react';
import { Search, Shield } from 'lucide-react';

export interface Application {
  package: string;
  label: string;
  stage1_only?: boolean;
  version?: string;
  installTime?: string;
  permissions?: string[];
  is_system?: boolean;
}

interface ApplicationExplorerProps {
  deviceSerial: string | null;
  selectedPackage?: string | null;
  onSelectApp?: (app: Application) => void;
}

export const ApplicationExplorer: React.FC<ApplicationExplorerProps> = ({
  deviceSerial,
  selectedPackage,
  onSelectApp
}) => {
  const [apps, setApps] = useState<Application[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedApp, setSelectedApp] = useState<Application | null>(null);
  const appListInFlightRef = useRef(false);

  useEffect(() => {
    if (deviceSerial) {
      loadApplications();
    } else {
      setApps([]);
      setSelectedApp(null);
    }
  }, [deviceSerial]);

  useEffect(() => {
    if (!selectedPackage) {
      setSelectedApp(null);
      return;
    }
    const match = apps.find((app) => app.package === selectedPackage);
    if (match) setSelectedApp(match);
  }, [apps, selectedPackage]);

  const loadApplications = async () => {
    if (!deviceSerial || appListInFlightRef.current || document.hidden) return;

    appListInFlightRef.current = true;
    setLoading(true);

    try {
      const response = await fetch(`/api/v1/device-lab/apps?serial=${encodeURIComponent(deviceSerial)}&include_system=false`);
      const data = await response.json();

      if (data.success) {
        setApps(data.apps || []);
      }
    } catch (error) {
      console.error('[ApplicationExplorer] Failed to load apps:', error);
    } finally {
      appListInFlightRef.current = false;
      setLoading(false);
    }
  };

  const handleSelect = (app: Application) => {
    setSelectedApp(app);
    onSelectApp?.(app);
  };

  const filteredApps = apps.filter((app) =>
    app.label?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    app.package?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="flex h-full min-h-0 flex-col bg-black text-white">
      <div className="border-b border-white/10 p-3">
        <label className="mb-2 block font-mono text-[10px] uppercase tracking-[0.18em] text-white/40">
          Search
        </label>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-white/35" />
          <input
            type="text"
            placeholder="Search applications"
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
            className="h-9 w-full border border-white/10 bg-white/[0.035] pl-10 pr-3 font-mono text-xs text-white placeholder:text-white/30 focus:border-white/35 focus:outline-none"
          />
        </div>
      </div>

      <div className="flex min-h-0 flex-1 flex-col">
        <div className="flex h-9 shrink-0 items-center justify-between border-b border-white/10 px-3">
          <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-white/40">Application List</span>
          <span className="font-mono text-[10px] text-white/35">{filteredApps.length}</span>
        </div>

        <div className="custom-scrollbar min-h-0 flex-1 overflow-y-auto">
          {loading && (
            <div className="flex h-full min-h-[180px] items-center justify-center">
              <div className="h-7 w-7 animate-spin rounded-full border border-white/15 border-t-white" />
            </div>
          )}

          {!loading && filteredApps.map((app) => {
            const isSelected = selectedPackage === app.package || selectedApp?.package === app.package;
            return (
              <button
                key={app.package}
                onClick={() => handleSelect(app)}
                className={`block w-full border-b border-white/10 p-3 text-left transition-colors hover:bg-white/[0.04] ${
                  isSelected ? 'bg-white/[0.075]' : ''
                }`}
              >
                <div className="flex items-start gap-3">
                  <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${isSelected ? 'bg-green-300' : 'bg-white/25'}`} />
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold text-white">{app.label || app.package}</div>
                    <div className="mt-1 truncate font-mono text-[11px] text-white/40">{app.package}</div>
                    {app.version && (
                      <div className="mt-1 font-mono text-[10px] uppercase tracking-[0.12em] text-white/30">
                        Version {app.version}
                      </div>
                    )}
                  </div>
                </div>
              </button>
            );
          })}

          {!loading && filteredApps.length === 0 && (
            <div className="flex h-full min-h-[180px] flex-col items-center justify-center px-6 text-center text-white/35">
              <Shield className="mb-3 h-10 w-10 opacity-60" />
              <p className="font-mono text-xs uppercase tracking-[0.14em]">
                {deviceSerial ? 'No applications found' : 'No device connected'}
              </p>
            </div>
          )}
        </div>
      </div>

      <div className="shrink-0 border-t border-white/10 p-3">
        <div className="mb-2 font-mono text-[10px] uppercase tracking-[0.18em] text-white/40">Selected App</div>
        {selectedApp ? (
          <div className="space-y-1">
            <div className="truncate text-sm font-semibold">{selectedApp.label || selectedApp.package}</div>
            <div className="break-all font-mono text-[11px] text-white/45">{selectedApp.package}</div>
            {selectedApp.version && (
              <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-white/35">
                Version {selectedApp.version}
              </div>
            )}
          </div>
        ) : (
          <div className="font-mono text-xs text-white/35">Select an application</div>
        )}
      </div>
    </div>
  );
};
