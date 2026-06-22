import React, { useState, useRef, useEffect } from 'react'
import GlassPanel from '../ui/GlassPanel'
import { ChatMessage } from '../../hooks/useNeuralLab'

interface AIChatInvestigatorProps {
  messages: ChatMessage[]
  chatLoading: boolean
  onSendMessage: (msg: string) => void
  onClearHistory: () => void
}

const STARTER_QUESTIONS = [
  'How can this APK steal banking credentials?',
  'Does this APK perform overlay attacks on banking apps?',
  'Can this APK intercept OTPs or read banking SMS?',
  'Which banking or fintech apps are targeted by this APK?',
  'What is the likelihood of account takeover (ATO)?',
  'Generate an executive report for a bank SOC team.',
]

export const AIChatInvestigator: React.FC<AIChatInvestigatorProps> = ({
  messages,
  chatLoading,
  onSendMessage,
  onClearHistory,
}) => {
  const [input, setInput] = useState('')
  const scrollRef = useRef<HTMLDivElement | null>(null)

  // Listen for 'explain-function' events from the console
  useEffect(() => {
    const handleExplain = (e: any) => {
      const funcName = e.detail;
      onSendMessage(`Analyze this function in detail: ${funcName}`);
    };
    window.addEventListener('explain-function', handleExplain);
    return () => window.removeEventListener('explain-function', handleExplain);
  }, [onSendMessage]);

  useEffect(() => {
    // Auto scroll chat to bottom
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages])

  const handleSend = () => {
    if (!input.trim() || chatLoading) return
    onSendMessage(input)
    setInput('')
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSend()
    }
  }

  return (
    <GlassPanel className="p-4 border-border bg-surface-variant/10 flex flex-col h-[500px] font-mono text-xs select-none">
      
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border pb-3 mb-3">
        <h4 className="font-semibold text-primary flex items-center gap-1.5 uppercase">
          <span className="material-symbols-outlined text-sm">psychology</span>
          Forensic Copilot Console
        </h4>
        <button
          onClick={onClearHistory}
          className="text-on-surface-variant hover:text-on-surface p-1 rounded"
          title="Clear Chat Workspace"
        >
          <span className="material-symbols-outlined text-sm block">delete</span>
        </button>
      </div>

      {/* Messages area */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto pr-1 mb-4 space-y-3 scrollbar-thin select-text"
      >
        {messages.length === 0 ? (
          <div className="py-8 text-center flex flex-col items-center justify-center opacity-60">
            <span className="material-symbols-outlined text-4xl text-primary mb-3">robot_2</span>
            <p className="font-semibold text-on-surface mb-2">Specter Forensics Assistant</p>
            <p className="text-[10px] text-on-surface-variant max-w-xs leading-normal mb-4">
              Ask questions about API calls, decompiled code flow, dynamic anomalies, or matching YARA rules.
            </p>
            
            {/* Starter queries */}
            <div className="w-full space-y-1.5 text-left font-mono">
              {STARTER_QUESTIONS.map((q) => (
                <button
                  key={q}
                  onClick={() => onSendMessage(q)}
                  className="w-full text-left p-2.5 rounded-md border border-border bg-surface/40 hover:bg-surface-variant/40 text-[10px] text-on-surface-variant hover:text-on-surface transition-colors"
                >
                  &gt; {q}
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((m) => (
            <div
              key={m.id}
              className={`p-3 rounded-lg border max-w-[90%] leading-relaxed ${
                m.role === 'user'
                  ? 'bg-primary/5 border-primary/20 text-on-surface ml-auto'
                  : 'bg-surface border-border text-on-surface mr-auto'
              }`}
            >
              <div className="flex justify-between items-center text-[8px] opacity-40 font-mono mb-1">
                <span>{m.role === 'user' ? 'ANALYST' : 'SPECTER_COGNITION'}</span>
                <span>{m.timestamp}</span>
              </div>
              <p className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed">{m.content}</p>
              
              {m.isStreaming && (
                <span className="inline-block w-1.5 h-3 bg-primary animate-pulse ml-0.5" />
              )}
            </div>
          ))
        )}
      </div>

      {/* Input bar */}
      <div className="flex items-center gap-2 mt-auto">
        <input
          type="text"
          placeholder="Ask Specter Neural Lab..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyPress}
          disabled={chatLoading}
          className="flex-1 bg-surface border border-border rounded-md py-2 px-3 focus:outline-none focus:border-primary text-on-surface"
        />
        <button
          onClick={handleSend}
          disabled={chatLoading || !input.trim()}
          className="btn-primary p-2 h-9 w-9 rounded-md flex items-center justify-center disabled:opacity-50"
        >
          <span className="material-symbols-outlined text-sm">send</span>
        </button>
      </div>
    </GlassPanel>
  )
}
export default AIChatInvestigator
