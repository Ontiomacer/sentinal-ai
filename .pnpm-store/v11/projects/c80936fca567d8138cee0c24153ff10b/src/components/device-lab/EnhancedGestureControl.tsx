/**
 * Enhanced Gesture Control for Device Lab
 * Supports: tap, double tap, long press, swipe, drag, scroll wheel
 */

import React, { useState, useRef } from 'react';

interface GestureControlProps {
  deviceSerial: string;
  deviceWidth: number;
  deviceHeight: number;
  screenRef: React.RefObject<HTMLDivElement>;
  children: React.ReactNode;
}

interface TouchPoint {
  x: number;
  y: number;
  timestamp: number;
}

export const EnhancedGestureControl: React.FC<GestureControlProps> = ({
  deviceSerial,
  deviceWidth,
  deviceHeight,
  screenRef,
  children
}) => {
  const [lastTouch, setLastTouch] = useState<TouchPoint | null>(null);
  const [longPressTimer, setLongPressTimer] = useState<ReturnType<typeof setTimeout> | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const dragStartRef = useRef<TouchPoint | null>(null);

  const convertToDeviceCoords = (clientX: number, clientY: number) => {
    if (!screenRef.current) return null;
    
    const rect = screenRef.current.getBoundingClientRect();
    const relativeX = (clientX - rect.left) / rect.width;
    const relativeY = (clientY - rect.top) / rect.height;
    
    return {
      x: Math.round(relativeX * deviceWidth),
      y: Math.round(relativeY * deviceHeight)
    };
  };

  const sendGesture = async (gestureType: string, x: number, y: number, x2?: number, y2?: number, duration?: number) => {
    try {
      const payload: any = {
        device_serial: deviceSerial,
        gesture_type: gestureType,
        x,
        y
      };

      if (x2 !== undefined) payload.x2 = x2;
      if (y2 !== undefined) payload.y2 = y2;
      if (duration !== undefined) payload.duration = duration;

      const response = await fetch('/api/v1/device-lab/control/gesture', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const result = await response.json();
      if (!result.success) {
        console.error(`[Gesture] ${gestureType} failed:`, result.message);
      }
    } catch (error) {
      console.error(`[Gesture] Failed to send ${gestureType}:`, error);
    }
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    const coords = convertToDeviceCoords(e.clientX, e.clientY);
    if (!coords) return;

    const touch: TouchPoint = {
      x: coords.x,
      y: coords.y,
      timestamp: Date.now()
    };

    dragStartRef.current = touch;

    // Start long press timer
    const timer = setTimeout(() => {
      console.log('[Gesture] Long press detected');
      sendGesture('long_press', coords.x, coords.y);
      dragStartRef.current = null; // Cancel drag
    }, 500);

    setLongPressTimer(timer);
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!dragStartRef.current) return;

    const coords = convertToDeviceCoords(e.clientX, e.clientY);
    if (!coords) return;

    // Check if moved enough to be considered a drag
    const dx = Math.abs(coords.x - dragStartRef.current.x);
    const dy = Math.abs(coords.y - dragStartRef.current.y);

    if (dx > 10 || dy > 10) {
      setIsDragging(true);
      if (longPressTimer) {
        clearTimeout(longPressTimer);
        setLongPressTimer(null);
      }
    }
  };

  const handleMouseUp = (e: React.MouseEvent) => {
    const coords = convertToDeviceCoords(e.clientX, e.clientY);
    if (!coords) return;

    // Clear long press timer
    if (longPressTimer) {
      clearTimeout(longPressTimer);
      setLongPressTimer(null);
    }

    // Handle drag/swipe
    if (isDragging && dragStartRef.current) {
      console.log('[Gesture] Swipe detected');
      sendGesture('swipe', dragStartRef.current.x, dragStartRef.current.y, coords.x, coords.y, 300);
      setIsDragging(false);
      dragStartRef.current = null;
      return;
    }

    // Handle tap vs double tap
    const now = Date.now();
    if (lastTouch && now - lastTouch.timestamp < 300) {
      // Double tap
      const tapDist = Math.sqrt(
        Math.pow(coords.x - lastTouch.x, 2) + 
        Math.pow(coords.y - lastTouch.y, 2)
      );

      if (tapDist < 50) {
        console.log('[Gesture] Double tap detected');
        sendGesture('double_tap', coords.x, coords.y);
        setLastTouch(null);
        dragStartRef.current = null;
        return;
      }
    }

    // Single tap
    if (!isDragging) {
      console.log('[Gesture] Tap detected');
      sendGesture('tap', coords.x, coords.y);
    }

    setLastTouch({ x: coords.x, y: coords.y, timestamp: now });
    setIsDragging(false);
    dragStartRef.current = null;
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    
    const coords = convertToDeviceCoords(e.clientX, e.clientY);
    if (!coords) return;

    // Convert wheel to swipe
    const scrollAmount = Math.abs(e.deltaY);
    const direction = e.deltaY > 0 ? 1 : -1;
    const distance = Math.min(scrollAmount, 500);

    // Vertical scroll
    if (Math.abs(e.deltaY) > Math.abs(e.deltaX)) {
      const y1 = coords.y;
      const y2 = coords.y + (direction * distance);
      console.log('[Gesture] Scroll wheel -> vertical swipe');
      sendGesture('swipe', coords.x, y1, coords.x, y2, 200);
    }
    // Horizontal scroll
    else {
      const scrollDir = e.deltaX > 0 ? 1 : -1;
      const x1 = coords.x;
      const x2 = coords.x + (scrollDir * distance);
      console.log('[Gesture] Scroll wheel -> horizontal swipe');
      sendGesture('swipe', x1, coords.y, x2, coords.y, 200);
    }
  };

  return (
    <div
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onWheel={handleWheel}
      style={{ cursor: isDragging ? 'grabbing' : 'pointer' }}
    >
      {children}
    </div>
  );
};
