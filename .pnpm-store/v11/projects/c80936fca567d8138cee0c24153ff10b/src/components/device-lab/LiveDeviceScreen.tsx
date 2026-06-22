import React, { useEffect, useRef, useState } from 'react';

interface Props {
  device: any;
  isRunning: boolean;
  isFullscreen?: boolean;
  onToggleFullscreen?: () => void;
}

type Point = { x: number; y: number };
type MirrorState = 'idle' | 'starting' | 'active' | 'error';

const LiveDeviceScreen: React.FC<Props> = ({
  device
}) => {
  const [mirrorState, setMirrorState] = useState<MirrorState>('idle');
  const [mirrorMessage, setMirrorMessage] = useState('Waiting for device');
  const [streamUrl, setStreamUrl] = useState<string | null>(null);
  const [isTouching, setIsTouching] = useState(false);
  const [orientation, setOrientation] = useState<'portrait' | 'landscape'>('portrait');
  const [swipeStart, setSwipeStart] = useState<Point | null>(null);
  const [swipeEnd, setSwipeEnd] = useState<Point | null>(null);
  const [isDrawingSwipe, setIsDrawingSwipe] = useState(false);
  const [displaySize, setDisplaySize] = useState({ width: 0, height: 0 });
  const [useTestFrame] = useState(true); // ALWAYS use test mode for now

  const screenRef = useRef<HTMLDivElement>(null);
  const displayRef = useRef<HTMLDivElement>(null);
  const mirrorPollRef = useRef<number | null>(null);
  const suppressClickRef = useRef(false);

  const deviceSerial = device?.serial;
  const deviceWidth = Number(device?.width || 720);
  const deviceHeight = Number(device?.height || 1600);

  // Test mode: Use static screenshot polling instead of MJPEG
  useEffect(() => {
    if (!useTestFrame || !deviceSerial) return;

    console.log('[LiveDeviceScreen] TEST MODE: Using static screenshots');
    let cancelled = false;

    const pollScreenshot = async () => {
      if (cancelled) return;
      
      const url = `http://localhost:8000/api/v1/device-lab/mirror/test-frame?serial=${encodeURIComponent(deviceSerial)}&t=${Date.now()}`;
      console.log('[LiveDeviceScreen] TEST MODE: Fetching', url);
      setStreamUrl(url);
      
      setTimeout(() => pollScreenshot(), 1000); // Poll every second
    };

    pollScreenshot();

    return () => {
      cancelled = true;
    };
  }, [useTestFrame, deviceSerial]);

  useEffect(() => {
    if (!displayRef.current) return;

    const updateSize = () => {
      const rect = displayRef.current?.getBoundingClientRect();
      if (rect) setDisplaySize({ width: rect.width, height: rect.height });
    };

    updateSize();
    const observer = new ResizeObserver(updateSize);
    observer.observe(displayRef.current);
    window.addEventListener('resize', updateSize);

    return () => {
      observer.disconnect();
      window.removeEventListener('resize', updateSize);
    };
  }, []);

  useEffect(() => {
    // Start mirroring when device is connected (not just when app is running)
    if (!deviceSerial || useTestFrame) {
      setMirrorState('idle');
      setMirrorMessage('Waiting for device');
      return;
    }

    let cancelled = false;

    const startMirror = async () => {
      setMirrorState('starting');
      setMirrorMessage('Starting scrcpy mirror transport');
      console.log('[LiveDeviceScreen] Starting mirror for device:', deviceSerial);

      try {
        const response = await fetch('/api/v1/device-lab/mirror/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ device_serial: deviceSerial })
        });
        const data = await response.json().catch(() => ({}));
        console.log('[LiveDeviceScreen] Mirror start response:', data);
        
        if (!response.ok || data.success === false) {
          throw new Error(data.detail || data.message || `Mirror failed (${response.status})`);
        }
        if (!cancelled) {
          const url = `http://localhost:8000/api/v1/device-lab/mirror/mjpeg?serial=${encodeURIComponent(deviceSerial)}&max_size=720&max_fps=24&t=${Date.now()}`;
          console.log('[LiveDeviceScreen] Setting stream URL:', url);
          setMirrorState(data.streaming ? 'active' : 'starting');
          setMirrorMessage(data.message || 'scrcpy mirror transport active');
          setStreamUrl(url);
        }
      } catch (error) {
        console.error('[LiveDeviceScreen] Mirror start error:', error);
        if (!cancelled) {
          setMirrorState('error');
          setMirrorMessage(error instanceof Error ? error.message : 'scrcpy mirror transport unavailable');
        }
      }
    };

    const pollMirror = async () => {
      if (cancelled || document.hidden) return;
      try {
        const response = await fetch(`/api/v1/device-lab/mirror/status?serial=${encodeURIComponent(deviceSerial)}`);
        const data = await response.json().catch(() => ({}));
        if (response.ok && data.success) {
          setMirrorState(data.streaming ? 'active' : 'idle');
          setMirrorMessage(data.streaming ? 'scrcpy mirror transport active' : 'scrcpy mirror transport idle');
        }
      } catch {
        if (!cancelled) {
          setMirrorState('error');
          setMirrorMessage('Unable to read scrcpy mirror status');
        }
      } finally {
        if (!cancelled) {
          mirrorPollRef.current = window.setTimeout(pollMirror, 3000);
        }
      }
    };

    startMirror().then(pollMirror);

    return () => {
      cancelled = true;
      setStreamUrl(null);
      if (mirrorPollRef.current) window.clearTimeout(mirrorPollRef.current);
      fetch('/api/v1/device-lab/mirror/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_serial: deviceSerial })
      }).catch(() => {});
    };
  }, [deviceSerial, useTestFrame]);  // Depend on useTestFrame too

  const getDevicePoint = (event: React.MouseEvent<HTMLDivElement>): Point | null => {
    if (!screenRef.current) return null;
    const rect = screenRef.current.getBoundingClientRect();
    const relativeX = Math.min(Math.max((event.clientX - rect.left) / rect.width, 0), 1);
    const relativeY = Math.min(Math.max((event.clientY - rect.top) / rect.height, 0), 1);

    return {
      x: Math.round(relativeX * deviceWidth),
      y: Math.round(relativeY * deviceHeight)
    };
  };

  const flashTouch = (duration = 200) => {
    setIsTouching(true);
    window.setTimeout(() => setIsTouching(false), duration);
  };

  const postControl = async (url: string, payload: Record<string, unknown>, label: string) => {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok || !result.success) {
        console.error(`[LiveDeviceScreen] ${label} failed:`, result.message || result.detail || `HTTP ${response.status}`);
      }
    } catch (error) {
      console.error(`[LiveDeviceScreen] ${label} failed:`, error);
    }
  };

  const handleScreenClick = async (event: React.MouseEvent<HTMLDivElement>) => {
    if (suppressClickRef.current) {
      suppressClickRef.current = false;
      return;
    }
    if (!device || swipeStart) return;

    const point = getDevicePoint(event);
    if (!point) return;

    flashTouch();
    await postControl('/api/v1/device-lab/control/tap', {
      device_serial: device.serial,
      x: point.x,
      y: point.y
    }, 'Tap');
  };

  const handleSwipeStart = (event: React.MouseEvent<HTMLDivElement>) => {
    if (!device) return;
    const point = getDevicePoint(event);
    if (!point) return;

    setSwipeStart(point);
    setSwipeEnd(null);
    setIsDrawingSwipe(true);
  };

  const handleSwipeMove = (event: React.MouseEvent<HTMLDivElement>) => {
    if (!swipeStart || !device) return;
    const point = getDevicePoint(event);
    if (point) setSwipeEnd(point);
  };

  const handleSwipeEnd = async (event: React.MouseEvent<HTMLDivElement>) => {
    if (!swipeStart || !device) {
      setSwipeStart(null);
      setSwipeEnd(null);
      setIsDrawingSwipe(false);
      return;
    }

    const endPoint = getDevicePoint(event);
    if (!endPoint) {
      setSwipeStart(null);
      setSwipeEnd(null);
      setIsDrawingSwipe(false);
      return;
    }

    const deltaX = Math.abs(endPoint.x - swipeStart.x);
    const deltaY = Math.abs(endPoint.y - swipeStart.y);
    const distance = Math.sqrt(deltaX * deltaX + deltaY * deltaY);

    if (distance > 50) {
      suppressClickRef.current = true;
      flashTouch(300);
      await postControl('/api/v1/device-lab/control/gesture', {
        device_serial: device.serial,
        gesture_type: 'swipe',
        x: swipeStart.x,
        y: swipeStart.y,
        x2: endPoint.x,
        y2: endPoint.y,
        duration: 300
      }, 'Swipe');
    }

    setSwipeStart(null);
    setSwipeEnd(null);
    setIsDrawingSwipe(false);
  };

  const sendKeyEvent = async (keycode: string) => {
    if (!device) return;
    await postControl('/api/v1/device-lab/control/key', {
      device_serial: device.serial,
      keycode
    }, keycode);
  };

  const toggleOrientation = () => {
    setOrientation((value) => value === 'portrait' ? 'landscape' : 'portrait');
  };

  const getDeviceDimensions = () => {
    const sourceWidth = orientation === 'portrait' ? deviceWidth : deviceHeight;
    const sourceHeight = orientation === 'portrait' ? deviceHeight : deviceWidth;
    const containerWidth = displaySize.width || 720;
    const containerHeight = displaySize.height || 640;
    const maxWidth = Math.max(containerWidth * 0.82, 300);
    const maxHeight = Math.max(containerHeight * 0.94, 420);
    const scale = Math.max(0.1, Math.min(maxWidth / sourceWidth, maxHeight / sourceHeight));

    return {
      width: Math.round(sourceWidth * scale),
      height: Math.round(sourceHeight * scale)
    };
  };

  const deviceDimensions = getDeviceDimensions();
  const frameWidth = orientation === 'portrait' ? deviceDimensions.width : deviceDimensions.height;
  const frameHeight = orientation === 'portrait' ? deviceDimensions.height : deviceDimensions.width;

  return (
    <div className="flex h-full min-h-0 flex-col bg-black text-white">
      <div className="flex h-10 flex-shrink-0 items-center justify-between border-b border-white/10 bg-black px-3">
        <div className="flex min-w-0 items-center gap-2">
          <span className="material-symbols-outlined text-sm text-white">smartphone</span>
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-white/45">Device Screen</span>
          {device && (
            <>
              <span className="text-white/20">/</span>
              <span className="truncate font-mono text-[11px] text-white/45">{device.model}</span>
            </>
          )}
        </div>

        <div className="flex items-center gap-1">
          <button onClick={() => sendKeyEvent('KEYCODE_BACK')} className="p-1.5 text-white/45 transition-colors hover:bg-white/[0.06] hover:text-white" title="Back">
            <span className="material-symbols-outlined text-base">arrow_back</span>
          </button>
          <button onClick={() => sendKeyEvent('KEYCODE_HOME')} className="p-1.5 text-white/45 transition-colors hover:bg-white/[0.06] hover:text-white" title="Home">
            <span className="material-symbols-outlined text-base">home</span>
          </button>
          <button onClick={() => sendKeyEvent('KEYCODE_APP_SWITCH')} className="p-1.5 text-white/45 transition-colors hover:bg-white/[0.06] hover:text-white" title="Recents">
            <span className="material-symbols-outlined text-base">apps</span>
          </button>
          <div className="mx-1 h-5 w-px bg-white/10" />
          <button onClick={toggleOrientation} className="p-1.5 text-white/45 transition-colors hover:bg-white/[0.06] hover:text-white" title="Rotate">
            <span className="material-symbols-outlined text-base">screen_rotation</span>
          </button>
          <button onClick={() => sendKeyEvent('KEYCODE_VOLUME_UP')} className="p-1.5 text-white/45 transition-colors hover:bg-white/[0.06] hover:text-white" title="Volume Up">
            <span className="material-symbols-outlined text-base">volume_up</span>
          </button>
          <button onClick={() => sendKeyEvent('KEYCODE_VOLUME_DOWN')} className="p-1.5 text-white/45 transition-colors hover:bg-white/[0.06] hover:text-white" title="Volume Down">
            <span className="material-symbols-outlined text-base">volume_down</span>
          </button>
          <button onClick={() => sendKeyEvent('KEYCODE_POWER')} className="p-1.5 text-white/45 transition-colors hover:bg-red-900/20 hover:text-red-300" title="Power">
            <span className="material-symbols-outlined text-base">power_settings_new</span>
          </button>
          {device && (
            <>
              <div className="mx-1 h-5 w-px bg-white/10" />
              <div className="flex items-center gap-2 px-2">
                <span className={`h-1.5 w-1.5 rounded-full ${mirrorState === 'active' ? 'animate-pulse bg-white' : mirrorState === 'error' ? 'bg-red-300' : 'bg-white/35'}`} />
                <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-white/70">
                  {mirrorState === 'active' ? 'Live' : mirrorState}
                </span>
                {/* DEBUG: Show stream URL status */}
                <span className="ml-2 font-mono text-[9px] text-white/40">
                  {streamUrl ? '✓ URL' : '✗ No URL'}
                </span>
              </div>
            </>
          )}
        </div>
      </div>

      <div ref={displayRef} className="flex flex-1 items-center justify-center overflow-hidden bg-[radial-gradient(ellipse_at_center,_rgba(255,255,255,0.045)_0%,_transparent_58%)] p-3" style={{ minHeight: 0 }}>
        {device ? (
          <div className="relative" style={{ width: deviceDimensions.width, height: deviceDimensions.height }}>
            <div
              className={`relative overflow-hidden rounded-[1.65rem] border border-white/15 bg-[#050505] shadow-2xl transition-all duration-300 ${orientation === 'portrait' ? '' : 'rotate-90'}`}
              style={{ width: frameWidth, height: frameHeight }}
            >
              {orientation === 'portrait' && (
                <div
                  className="absolute left-1/2 top-0 z-10 -translate-x-1/2 rounded-b-2xl bg-black"
                  style={{
                    width: `${(deviceDimensions.width / 360) * 128}px`,
                    height: `${(deviceDimensions.width / 360) * 24}px`
                  }}
                />
              )}

              <div
                ref={screenRef}
                onClick={handleScreenClick}
                onMouseDown={handleSwipeStart}
                onMouseMove={handleSwipeMove}
                onMouseUp={handleSwipeEnd}
                onMouseLeave={handleSwipeEnd}
                className={`absolute inset-2 cursor-pointer overflow-hidden rounded-[1.25rem] bg-black transition-all ${isTouching ? 'ring-4 ring-white/35' : ''} ${isDrawingSwipe ? 'cursor-grabbing' : 'cursor-grab'}`}
                title="Click to tap / drag to swipe"
              >
                <div className="relative flex h-full w-full items-center justify-center bg-black">
                  {streamUrl && (
                    <img
                      ref={(el) => {
                        if (el) {
                          console.log('[LiveDeviceScreen] IMG element created');
                          console.log('[LiveDeviceScreen] IMG src:', el.src);
                          console.log('[LiveDeviceScreen] IMG width:', el.width, 'height:', el.height);
                          console.log('[LiveDeviceScreen] IMG naturalWidth:', el.naturalWidth, 'naturalHeight:', el.naturalHeight);
                          console.log('[LiveDeviceScreen] IMG complete:', el.complete);
                          console.log('[LiveDeviceScreen] IMG offsetWidth:', el.offsetWidth, 'offsetHeight:', el.offsetHeight);
                          console.log('[LiveDeviceScreen] IMG computed style:', window.getComputedStyle(el).display, window.getComputedStyle(el).visibility, window.getComputedStyle(el).opacity);
                        }
                      }}
                      src={streamUrl}
                      alt="Android device live mirror"
                      className="pointer-events-none absolute inset-0 h-full w-full select-none object-contain"
                      draggable={false}
                      onLoad={(e) => {
                        const img = e.currentTarget;
                        console.log('[LiveDeviceScreen] STREAM IMAGE LOADED');
                        console.log('[LiveDeviceScreen] Loaded naturalWidth:', img.naturalWidth, 'naturalHeight:', img.naturalHeight);
                        console.log('[LiveDeviceScreen] Loaded width:', img.width, 'height:', img.height);
                        console.log('[LiveDeviceScreen] Loaded offsetWidth:', img.offsetWidth, 'offsetHeight:', img.offsetHeight);
                        setMirrorState('active');
                        setMirrorMessage('Live Android screen stream');
                      }}
                      onError={(e) => {
                        const img = e.currentTarget;
                        console.error('[LiveDeviceScreen] STREAM IMAGE ERROR');
                        console.error('[LiveDeviceScreen] Error type:', e.type);
                        console.error('[LiveDeviceScreen] IMG src:', img.src);
                        console.error('[LiveDeviceScreen] IMG naturalWidth:', img.naturalWidth, 'naturalHeight:', img.naturalHeight);
                        setMirrorState('error');
                        setMirrorMessage('Live stream failed to decode');
                      }}
                    />
                  )}
                  {!streamUrl && <div className="absolute inset-0 opacity-20" style={{
                    backgroundImage: 'linear-gradient(rgba(255,255,255,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.08) 1px, transparent 1px)',
                    backgroundSize: '24px 24px'
                  }} />}
                  {(!streamUrl || mirrorState === 'starting' || mirrorState === 'error') && <div className="relative z-10 max-w-[78%] text-center">
                    <div className="mb-3 font-mono text-[10px] uppercase tracking-[0.2em] text-white/35">
                      {deviceWidth} x {deviceHeight}
                    </div>
                    <div className="text-sm font-semibold uppercase tracking-[0.16em] text-white">
                      {mirrorState === 'active' ? 'live screen stream' : mirrorState === 'starting' ? 'starting scrcpy stream' : mirrorState === 'error' ? 'mirror unavailable' : 'mirror idle'}
                    </div>
                    <p className="mt-3 font-mono text-[11px] leading-5 text-white/45">{mirrorMessage}</p>
                  </div>}

                  {isDrawingSwipe && swipeStart && swipeEnd && (
                    <svg className="pointer-events-none absolute inset-0 z-20 h-full w-full">
                      <defs>
                        <marker id="arrowhead" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
                          <polygon points="0 0, 10 3, 0 6" fill="#ffffff" />
                        </marker>
                      </defs>
                      <line
                        x1={`${(swipeStart.x / deviceWidth) * 100}%`}
                        y1={`${(swipeStart.y / deviceHeight) * 100}%`}
                        x2={`${(swipeEnd.x / deviceWidth) * 100}%`}
                        y2={`${(swipeEnd.y / deviceHeight) * 100}%`}
                        stroke="#ffffff"
                        strokeWidth="3"
                        markerEnd="url(#arrowhead)"
                      />
                      <circle cx={`${(swipeStart.x / deviceWidth) * 100}%`} cy={`${(swipeStart.y / deviceHeight) * 100}%`} r="8" fill="#ffffff" opacity="0.5" />
                    </svg>
                  )}
                  {isTouching && <div className="pointer-events-none absolute inset-0 z-20 bg-white/10" />}
                </div>
              </div>

              {orientation === 'portrait' && (
                <>
                  <div className="absolute right-0 top-32 h-16 w-1 bg-white/15" />
                  <div className="absolute left-0 top-28 h-10 w-1 bg-white/15" />
                  <div className="absolute left-0 top-44 h-10 w-1 bg-white/15" />
                </>
              )}
            </div>
          </div>
        ) : (
          <div className="text-center">
            <div className="relative mx-auto mb-4 h-20 w-20">
              <div className="absolute inset-0 border border-white/15 bg-white/[0.025]" />
              <span className="material-symbols-outlined absolute inset-0 m-auto text-4xl text-white/30">phone_disabled</span>
            </div>
            <p className="mb-2 font-mono text-xs uppercase tracking-[0.16em] text-white/45">No device connected</p>
            <p className="font-mono text-[11px] uppercase tracking-[0.14em] text-white/25">Connect Android device via ADB</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default LiveDeviceScreen;
