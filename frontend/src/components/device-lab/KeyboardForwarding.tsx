/**
 * Keyboard Forwarding to Android Device
 * Captures keyboard input and sends to device via ADB
 */

import React, { useEffect, useState } from 'react';

interface KeyboardForwardingProps {
  deviceSerial: string | null;
  enabled: boolean;
}

export const KeyboardForwarding: React.FC<KeyboardForwardingProps> = ({
  deviceSerial,
  enabled
}) => {
  const [buffer, setBuffer] = useState('');

  useEffect(() => {
    if (!enabled || !deviceSerial) return;

    const handleKeyDown = async (e: KeyboardEvent) => {
      // Ignore modifier keys alone
      if (['Control', 'Alt', 'Shift', 'Meta'].includes(e.key)) return;

      // Handle special keys
      if (e.key === 'Enter') {
        e.preventDefault();
        await sendKeyEvent('KEYCODE_ENTER');
        return;
      }

      if (e.key === 'Backspace') {
        e.preventDefault();
        await sendKeyEvent('KEYCODE_DEL');
        return;
      }

      if (e.key === 'Escape') {
        e.preventDefault();
        await sendKeyEvent('KEYCODE_BACK');
        return;
      }

      // Skip function keys
      if (e.key.startsWith('F') && e.key.length <= 3) return;

      // Handle regular text input
      if (e.key.length === 1 && !e.ctrlKey && !e.altKey && !e.metaKey) {
        e.preventDefault();
        await sendText(e.key);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [enabled, deviceSerial]);

  const sendText = async (text: string) => {
    if (!deviceSerial) return;

    try {
      const response = await fetch('/api/v1/device-lab/control/text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_serial: deviceSerial,
          text: text
        })
      });

      const result = await response.json();
      if (result.success) {
        setBuffer(prev => prev + text);
        setTimeout(() => setBuffer(''), 2000);
      }
    } catch (error) {
      console.error('[Keyboard] Failed to send text:', error);
    }
  };

  const sendKeyEvent = async (keycode: string) => {
    if (!deviceSerial) return;

    try {
      const response = await fetch('/api/v1/device-lab/control/key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_serial: deviceSerial,
          keycode
        })
      });

      const result = await response.json();
      if (!result.success) {
        console.error('[Keyboard] Key event failed:', result.message);
      }
    } catch (error) {
      console.error('[Keyboard] Failed to send key:', error);
    }
  };

  if (!enabled) return null;

  return (
    <div className="fixed bottom-4 right-4 bg-gray-800 border border-green-500 rounded px-3 py-2 text-sm text-green-400 shadow-lg">
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
        <span>Keyboard Active</span>
      </div>
      {buffer && (
        <div className="mt-1 text-xs text-gray-400 font-mono">
          {buffer}
        </div>
      )}
    </div>
  );
};
