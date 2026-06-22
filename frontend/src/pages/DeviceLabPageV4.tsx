import React, { useEffect, useRef, useState } from 'react';
import { ArrowRight, ChevronDown, Keyboard, Loader2, Play, Square, Smartphone } from 'lucide-react';
import LiveDeviceScreen from '../components/device-lab/LiveDeviceScreen';
import { Application, ApplicationExplorer } from '../components/device-lab/ApplicationExplorer';
import { RuntimeMonitor } from '../components/device-lab/RuntimeMonitor';
import { KeyboardForwarding } from '../components/device-lab/KeyboardForwarding';

type ExtractionStatus = 'standby' | 'extracting' | 'cached';

const DeviceLabPageV4: React.FC = () => {
  const devicePollInFlightRef = useRef(false);
  const devicePollDelayRef = useRef(3000);
  const devicePollFailureLoggedRef = useRef(false);
  const extractionInFlightRef = useRef(false);

  const [connectedDevice, setConnectedDevice] = useState<any>(null);
  const [selectedApp, setSelectedApp] = useState<Application | null>(null);
  const [keyboardEnabled, setKeyboardEnabled] = useState(false);
  const [runtimeOpen, setRuntimeOpen] = useState(false);
  const [extractionStatus, setExtractionStatus] = useState<ExtractionStatus>('standby');
  const [extractionError, setExtractionError] = useState<string | null>(null);
  const [analysisId, setAnalysisId] = useState<string | null>(null);
  const [cachedSha256, setCachedSha256] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    let timeoutId: number | undefined;

    const scheduleNextPoll = (delay: number) => {
      if (timeoutId) window.clearTimeout(timeoutId);
      timeoutId = window.setTimeout(pollDevices, delay);
    };

    const pollDevices = async () => {
      if (cancelled) return;
      if (document.hidden) {
        scheduleNextPoll(5000);
        return;
      }
      if (devicePollInFlightRef.current) return;

      devicePollInFlightRef.current = true;
      try {
        const response = await fetch('/api/v1/device-lab/devices');
        if (!response.ok) {
          throw new Error(`Device polling failed (${response.status})`);
        }
        const data = await response.json();
        const nextDevice = data.success && data.devices?.length > 0 ? data.devices[0] : null;
        setConnectedDevice((current: any) => {
          if (!current && !nextDevice) return current;
          if (current?.serial === nextDevice?.serial && current?.model === nextDevice?.model) return current;
          return nextDevice;
        });
        devicePollDelayRef.current = 3000;
        devicePollFailureLoggedRef.current = false;
      } catch (error) {
        if (!devicePollFailureLoggedRef.current) {
          console.warn('[DeviceLabV4] Device polling paused until backend is reachable:', error);
          devicePollFailureLoggedRef.current = true;
        }
        devicePollDelayRef.current = Math.min(devicePollDelayRef.current * 2, 30000);
      } finally {
        devicePollInFlightRef.current = false;
        if (!cancelled) {
          scheduleNextPoll(devicePollDelayRef.current);
        }
      }
    };

    pollDevices();
    const handleVisibilityChange = () => {
      if (!document.hidden) {
        devicePollDelayRef.current = 3000;
        scheduleNextPoll(0);
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      cancelled = true;
      if (timeoutId) window.clearTimeout(timeoutId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, []);

  useEffect(() => {
    setExtractionStatus('standby');
    setExtractionError(null);
    setAnalysisId(null);
    setCachedSha256(null);
  }, [selectedApp?.package]);

  const launchSelectedApp = async () => {
    if (!connectedDevice?.serial || !selectedApp?.package) return;

    try {
      const response = await fetch(
        `/api/v1/device-lab/apps/launch?serial=${encodeURIComponent(connectedDevice.serial)}&package=${encodeURIComponent(selectedApp.package)}`,
        { method: 'POST' }
      );
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.success === false) {
        throw new Error(data?.detail || data?.message || `Launch failed (${response.status})`);
      }
    } catch (error) {
      console.error('[DeviceLabV4] Launch failed:', error);
      setExtractionError(error instanceof Error ? error.message : 'Launch failed');
    }
  };

  const stopSelectedApp = async () => {
    if (!connectedDevice?.serial || !selectedApp?.package) return;

    try {
      const response = await fetch(
        `/api/v1/device-lab/apps/stop?serial=${encodeURIComponent(connectedDevice.serial)}&package=${encodeURIComponent(selectedApp.package)}`,
        { method: 'POST' }
      );
      const data = await response.json().catch(() => ({}));
      if (!response.ok || data.success === false) {
        throw new Error(data?.detail || data?.message || `Stop failed (${response.status})`);
      }
    } catch (error) {
      console.error('[DeviceLabV4] Stop failed:', error);
      setExtractionError(error instanceof Error ? error.message : 'Stop failed');
    }
  };

  const extractSelectedApk = async () => {
    if (!connectedDevice?.serial || !selectedApp?.package || extractionInFlightRef.current) return;

    extractionInFlightRef.current = true;
    setExtractionStatus('extracting');
    setExtractionError(null);
    setAnalysisId(null);
    setCachedSha256(null);

    try {
      const response = await fetch(
        `/api/v1/app-analysis/quick-scan?package_name=${encodeURIComponent(selectedApp.package)}&serial=${encodeURIComponent(connectedDevice.serial)}`,
        { method: 'POST' }
      );
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data?.detail || data?.error || `APK extraction failed (${response.status})`);
      }
      if (!data?.analysis_id) {
        throw new Error('APK extraction completed but analysis_id was not returned');
      }

      setExtractionStatus('cached');
      setAnalysisId(data.analysis_id);
      setCachedSha256(data.sha256 || data.quick_scan?.sha256 || null);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'APK extraction failed';
      console.error('[DeviceLabV4] APK extraction failed:', error);
      setExtractionError(message);
      setExtractionStatus('standby');
    } finally {
      extractionInFlightRef.current = false;
    }
  };

  const openInvestigationWorkspace = () => {
    if (!analysisId) {
      setExtractionError('Extract APK before opening the investigation workspace');
      return;
    }

    const params = new URLSearchParams();
    if (selectedApp?.package) params.set('package', selectedApp.package);
    if (connectedDevice?.serial) params.set('serial', connectedDevice.serial);
    if (cachedSha256) params.set('sha256', cachedSha256);

    const targetUrl = `/app-analysis/${encodeURIComponent(analysisId)}${params.toString() ? `?${params.toString()}` : ''}`;
    const workspace = window.open(targetUrl, '_blank');
    if (workspace) {
      workspace.opener = null;
    } else {
      setExtractionError('Browser blocked the investigation workspace window');
    }
  };

  const deviceReady = Boolean(connectedDevice?.serial);
  const appReady = Boolean(selectedApp?.package);
  const actionDisabled = !deviceReady || !appReady || extractionStatus === 'extracting';
  const appStatus = !selectedApp
    ? 'No app selected'
    : extractionStatus === 'extracting'
      ? 'Extracting APK'
      : extractionStatus === 'cached'
        ? 'APK cached'
        : selectedApp.stage1_only
          ? 'Indexed'
          : 'Installed';

  return (
    <div data-testid="device-lab-root" className="flex min-h-[calc(100vh-7.5rem)] flex-col bg-black text-white">
      <header className="shrink-0 border-t border-b border-white/10 bg-black px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center border border-white/15 bg-white/[0.03]">
              <Smartphone className="h-4 w-4" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-semibold uppercase tracking-[0.22em]">Device Lab</h1>
                <span className={`h-1.5 w-1.5 rounded-full ${connectedDevice ? 'bg-green-400' : 'bg-red-400'}`} />
              </div>
              <p className="truncate font-mono text-[11px] uppercase tracking-[0.16em] text-white/45">
                {connectedDevice ? `${connectedDevice.model} / ${connectedDevice.serial}` : 'ADB device interaction / no device connected'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setRuntimeOpen((value) => !value)}
              className="flex items-center gap-2 border border-white/10 bg-white/[0.04] px-3 py-2 text-xs font-semibold uppercase tracking-[0.12em] text-white/65 hover:text-white"
            >
              Runtime
              <ChevronDown className={`h-3.5 w-3.5 transition-transform ${runtimeOpen ? 'rotate-180' : ''}`} />
            </button>
            <button
              onClick={() => setKeyboardEnabled((value) => !value)}
              className={`flex items-center gap-2 px-3 py-2 text-xs font-semibold uppercase tracking-[0.12em] transition-colors ${
                keyboardEnabled ? 'bg-white text-black' : 'border border-white/10 bg-white/[0.04] text-white/65 hover:text-white'
              }`}
            >
              <Keyboard className="h-3.5 w-3.5" />
              Keyboard
            </button>
          </div>
        </div>
      </header>

      <div
        className="grid min-h-0 shrink-0 grid-cols-[20%_60%_20%] bg-black"
        style={{ height: 'clamp(560px, calc(100vh - 10.75rem), 820px)' }}
      >
        <aside data-testid="device-lab-left" className="min-h-0 border-r border-white/10 bg-[#030303]">
          <ApplicationExplorer
            deviceSerial={connectedDevice?.serial || null}
            selectedPackage={selectedApp?.package}
            onSelectApp={setSelectedApp}
          />
        </aside>

        <main data-testid="device-lab-center" className="min-h-0 bg-[#010101]">
          <LiveDeviceScreen
            device={connectedDevice}
            isRunning={Boolean(connectedDevice)}
          />
        </main>

        <aside data-testid="device-lab-right" className="custom-scrollbar min-h-0 overflow-y-auto border-l border-white/10 bg-[#030303]">
          <div className="space-y-4 p-4">
            <div>
              <h2 className="text-sm font-semibold uppercase tracking-[0.18em]">Device Controls</h2>
              <p className="mt-1 font-mono text-[11px] uppercase tracking-[0.14em] text-white/35">
                Operate selected package
              </p>
            </div>

            <section className="border border-white/10 bg-white/[0.025] p-3">
              <div className="mb-3 font-mono text-[10px] uppercase tracking-[0.18em] text-white/35">Selected App</div>
              {selectedApp ? (
                <div className="space-y-3">
                  <div>
                    <div className="truncate text-sm font-semibold text-white">{selectedApp.label || selectedApp.package}</div>
                    <div className="mt-1 break-all font-mono text-[11px] leading-4 text-white/45">{selectedApp.package}</div>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="bg-white/[0.035] p-2">
                      <div className="font-mono text-[9px] uppercase tracking-[0.16em] text-white/30">Version</div>
                      <div className="mt-1 truncate font-mono text-[11px] text-white/70">{selectedApp.version || 'Unknown'}</div>
                    </div>
                    <div className="bg-white/[0.035] p-2">
                      <div className="font-mono text-[9px] uppercase tracking-[0.16em] text-white/30">Status</div>
                      <div className="mt-1 truncate font-mono text-[11px] text-white/70">{appStatus}</div>
                    </div>
                  </div>
                </div>
              ) : (
                <p className="font-mono text-xs text-white/35">Select an application from the explorer.</p>
              )}
            </section>

            <section className="grid gap-2">
              <button
                onClick={launchSelectedApp}
                disabled={actionDisabled}
                className="flex items-center justify-center gap-2 border border-white/10 bg-white/[0.04] px-3 py-2.5 text-xs font-semibold uppercase tracking-[0.12em] text-white/75 hover:text-white disabled:cursor-not-allowed disabled:opacity-35"
              >
                <Play className="h-3.5 w-3.5" />
                Launch
              </button>
              <button
                onClick={stopSelectedApp}
                disabled={actionDisabled}
                className="flex items-center justify-center gap-2 border border-white/10 bg-white/[0.04] px-3 py-2.5 text-xs font-semibold uppercase tracking-[0.12em] text-white/75 hover:text-white disabled:cursor-not-allowed disabled:opacity-35"
              >
                <Square className="h-3.5 w-3.5" />
                Stop
              </button>
              <button
                onClick={extractSelectedApk}
                disabled={actionDisabled}
                className="flex items-center justify-center gap-2 bg-white px-3 py-2.5 text-xs font-semibold uppercase tracking-[0.12em] text-black hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-35"
              >
                {extractionStatus === 'extracting' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Smartphone className="h-3.5 w-3.5" />}
                Extract APK
              </button>
              <button
                onClick={openInvestigationWorkspace}
                disabled={!analysisId || extractionStatus === 'extracting'}
                className="flex items-center justify-center gap-2 border border-green-400/35 bg-green-400/10 px-3 py-2.5 text-xs font-semibold uppercase tracking-[0.12em] text-green-100 hover:bg-green-400/15 disabled:cursor-not-allowed disabled:border-white/10 disabled:bg-white/[0.025] disabled:text-white/30"
              >
                Analyze APK
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </section>

            <section className="border border-white/10 bg-white/[0.025] p-3">
              <div className="mb-3 font-mono text-[10px] uppercase tracking-[0.18em] text-white/35">Workflow</div>
              <div className="space-y-2 font-mono text-[11px] uppercase tracking-[0.12em]">
                <div className={appReady ? 'text-green-300' : 'text-white/35'}>1. Select App</div>
                <div className={extractionStatus !== 'standby' ? 'text-green-300' : 'text-white/35'}>2. Extract APK</div>
                <div className={cachedSha256 ? 'text-green-300' : 'text-white/35'}>3. Cache APK</div>
                <div className={analysisId ? 'text-green-300' : 'text-white/35'}>4. Open Investigation Workspace</div>
              </div>
            </section>

            {cachedSha256 && (
              <section className="border border-green-400/25 bg-green-400/10 p-3">
                <div className="mb-1 font-mono text-[10px] uppercase tracking-[0.18em] text-green-200/70">Cached SHA256</div>
                <div className="break-all font-mono text-[11px] text-green-100">{cachedSha256}</div>
              </section>
            )}

            {extractionError && (
              <section className="border border-red-400/35 bg-red-500/10 p-3 text-xs text-red-100">
                {extractionError}
              </section>
            )}
          </div>
        </aside>
      </div>

      <section data-testid="device-lab-runtime-drawer" className="shrink-0 border-t border-white/10 bg-black">
        <button
          onClick={() => setRuntimeOpen((value) => !value)}
          className="flex h-10 w-full items-center justify-between px-4 text-left font-mono text-[11px] uppercase tracking-[0.16em] text-white/55 hover:text-white"
        >
          <span>Runtime Drawer</span>
          <span className="flex items-center gap-2">
            {runtimeOpen ? 'Collapse' : 'Expand'}
            <ChevronDown className={`h-3.5 w-3.5 transition-transform ${runtimeOpen ? 'rotate-180' : ''}`} />
          </span>
        </button>
        {runtimeOpen && (
          <div className="custom-scrollbar h-[min(38vh,360px)] min-h-[220px] overflow-y-auto border-t border-white/10">
            <RuntimeMonitor
              deviceSerial={connectedDevice?.serial || null}
              packageName={selectedApp?.package}
            />
          </div>
        )}
      </section>

      <KeyboardForwarding deviceSerial={connectedDevice?.serial} enabled={keyboardEnabled} />
    </div>
  );
};

export default DeviceLabPageV4;
