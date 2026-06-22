/**
 * Runtime Monitoring Dashboard
 * Live monitoring of activities, services, processes, network connections
 */

import React, { useState, useEffect, useRef } from 'react';
import { Activity, Server, Cpu, Wifi, RefreshCw } from 'lucide-react';

interface RuntimeMonitorProps {
  deviceSerial: string | null;
  packageName?: string;
}

export const RuntimeMonitor: React.FC<RuntimeMonitorProps> = ({
  deviceSerial,
  packageName
}) => {
  const [activeTab, setActiveTab] = useState<'activities' | 'services' | 'processes' | 'network'>('activities');
  const [activities, setActivities] = useState<any[]>([]);
  const [services, setServices] = useState<any[]>([]);
  const [processes, setProcesses] = useState<any[]>([]);
  const [network, setNetwork] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const requestInFlightRef = useRef(false);

  useEffect(() => {
    if (!deviceSerial || !autoRefresh) return;

    const interval = setInterval(() => {
      refreshData();
    }, 3000);

    refreshData();

    return () => clearInterval(interval);
  }, [deviceSerial, activeTab, autoRefresh]);

  const refreshData = async () => {
    if (!deviceSerial || requestInFlightRef.current || document.hidden) return;

    requestInFlightRef.current = true;
    setLoading(true);

    try {
      switch (activeTab) {
        case 'activities':
          await fetchActivities();
          break;
        case 'services':
          await fetchServices();
          break;
        case 'processes':
          await fetchProcesses();
          break;
        case 'network':
          await fetchNetwork();
          break;
      }
    } finally {
      requestInFlightRef.current = false;
      setLoading(false);
    }
  };

  const fetchActivities = async () => {
    if (!deviceSerial) return;

    try {
      const response = await fetch(`/api/v1/device-lab/runtime/activities?serial=${deviceSerial}`);
      const data = await response.json();

      if (data.success) {
        setActivities(data.activities || []);
      }
    } catch (error) {
      console.error('[RuntimeMonitor] Failed to fetch activities:', error);
    }
  };

  const fetchServices = async () => {
    if (!deviceSerial) return;

    try {
      const url = packageName
        ? `/api/v1/device-lab/runtime/services?serial=${deviceSerial}&package=${packageName}`
        : `/api/v1/device-lab/runtime/services?serial=${deviceSerial}`;

      const response = await fetch(url);
      const data = await response.json();

      if (data.success) {
        setServices(data.services || []);
      }
    } catch (error) {
      console.error('[RuntimeMonitor] Failed to fetch services:', error);
    }
  };

  const fetchProcesses = async () => {
    if (!deviceSerial) return;

    try {
      const response = await fetch(`/api/v1/device-lab/runtime/processes?serial=${deviceSerial}`);
      const data = await response.json();

      if (data.success) {
        setProcesses(data.processes || []);
      }
    } catch (error) {
      console.error('[RuntimeMonitor] Failed to fetch processes:', error);
    }
  };

  const fetchNetwork = async () => {
    if (!deviceSerial) return;

    try {
      const response = await fetch(`/api/v1/device-lab/runtime/network?serial=${deviceSerial}`);
      const data = await response.json();

      if (data.success) {
        setNetwork(data.connections || []);
      }
    } catch (error) {
      console.error('[RuntimeMonitor] Failed to fetch network:', error);
    }
  };

  const tabs = [
    { id: 'activities', label: 'Activities', icon: Activity },
    { id: 'services', label: 'Services', icon: Server },
    { id: 'processes', label: 'Processes', icon: Cpu },
    { id: 'network', label: 'Network', icon: Wifi }
  ];

  return (
    <div className="flex h-full flex-col bg-black text-white">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 border-b border-white/10 p-3">
        <h3 className="text-sm font-semibold uppercase tracking-[0.16em] text-white">Runtime</h3>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-[0.12em] transition-colors ${
              autoRefresh
                ? 'bg-white text-black'
                : 'border border-white/10 bg-white/[0.04] text-white/45'
            }`}
          >
            Auto {autoRefresh ? 'On' : 'Off'}
          </button>
          <button
            onClick={refreshData}
            disabled={loading}
            className="border border-white/10 bg-white/[0.04] p-1.5 text-white/70 transition-colors hover:text-white disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-white/10 bg-[#050505]">
        {tabs.map(tab => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex flex-1 items-center justify-center gap-1.5 px-2 py-2 text-[11px] transition-colors ${
                activeTab === tab.id
                  ? 'bg-white text-black'
                  : 'text-white/45 hover:bg-white/[0.05] hover:text-white'
              }`}
            >
              <Icon className="h-3.5 w-3.5" />
              <span className="hidden xl:inline">{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Content */}
      <div className="custom-scrollbar flex-1 overflow-y-auto p-3">
        {activeTab === 'activities' && (
          <div className="space-y-2">
            {activities.length === 0 ? (
              <p className="py-6 text-center font-mono text-xs uppercase tracking-[0.14em] text-white/35">No activities detected</p>
            ) : (
              activities.map((activity, index) => (
                <div key={index} className="border border-white/10 bg-white/[0.035] p-2 text-sm">
                  <code className="text-white/80">{activity}</code>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'services' && (
          <div className="space-y-2">
            {services.length === 0 ? (
              <p className="py-6 text-center font-mono text-xs uppercase tracking-[0.14em] text-white/35">No services detected</p>
            ) : (
              services.map((service, index) => (
                <div key={index} className="border border-white/10 bg-white/[0.035] p-2">
                  <div className="text-sm font-medium text-white">{service.name || service.service || service}</div>
                  {service.package && (
                    <div className="mt-1 font-mono text-[11px] text-white/40">{service.package}</div>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'processes' && (
          <div className="space-y-2">
            {processes.length === 0 ? (
              <p className="py-6 text-center font-mono text-xs uppercase tracking-[0.14em] text-white/35">No processes detected</p>
            ) : (
              processes.map((process, index) => (
                <div key={index} className="flex items-center justify-between border border-white/10 bg-white/[0.035] p-2">
                  <div>
                    <div className="text-sm font-medium text-white">{process.name || process.process || process}</div>
                    {process.pid && (
                      <div className="mt-1 font-mono text-[11px] text-white/40">PID: {process.pid}</div>
                    )}
                  </div>
                  {process.cpu && (
                    <div className="font-mono text-sm text-white">{process.cpu}%</div>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'network' && (
          <div className="space-y-2">
            {network.length === 0 ? (
              <p className="py-6 text-center font-mono text-xs uppercase tracking-[0.14em] text-white/35">No network connections detected</p>
            ) : (
              network.map((conn, index) => (
                <div key={index} className="border border-white/10 bg-white/[0.035] p-2">
                  <div className="flex items-center justify-between">
                    <div className="text-sm font-medium text-white">{conn.remote || conn.address || conn}</div>
                    {conn.state && (
                      <span className="border border-white/10 bg-white/[0.08] px-2 py-1 font-mono text-[10px] uppercase text-white/70">
                        {conn.state}
                      </span>
                    )}
                  </div>
                  {conn.local && (
                    <div className="mt-1 font-mono text-[11px] text-white/40">Local: {conn.local}</div>
                  )}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
};
