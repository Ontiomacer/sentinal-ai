import React, { useState } from 'react'
import GlassPanel from '../ui/GlassPanel'
import { Investigation, InvestigationNote, InvestigationBookmark } from '../../services/neuralApi'

interface InvestigationSidebarProps {
  investigations: Investigation[]
  activeInvestigation: Investigation | null
  notes: InvestigationNote[]
  bookmarks: InvestigationBookmark[]
  onSwitch: (inv: Investigation) => void
  onCreate: (title: string, description: string, analystName: string) => void
  onAddNote: (content: string, type: string) => void
}

export const InvestigationSidebar: React.FC<InvestigationSidebarProps> = ({
  investigations,
  activeInvestigation,
  notes,
  bookmarks,
  onSwitch,
  onCreate,
  onAddNote,
}) => {
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newDesc, setNewDesc] = useState('')
  const [analyst, setAnalyst] = useState('Analyst')

  const [noteContent, setNoteContent] = useState('')
  const [noteType, setNoteType] = useState('general')

  const handleCreate = () => {
    if (!newTitle.trim()) return
    onCreate(newTitle, newDesc, analyst)
    setShowCreateForm(false)
    setNewTitle('')
    setNewDesc('')
  }

  const handleAddNote = () => {
    if (!noteContent.trim()) return
    onAddNote(noteContent, noteType)
    setNoteContent('')
  }

  return (
    <div className="flex flex-col gap-6 font-mono text-xs select-none h-full">
      {/* Session Manager */}
      <GlassPanel className="p-4 border-border bg-surface-variant/5 flex flex-col max-h-[200px]">
        <div className="flex justify-between items-center border-b border-border pb-2 mb-2">
          <span className="font-bold text-primary">INVESTIGATIONS</span>
          <button
            onClick={() => setShowCreateForm(!showCreateForm)}
            className="text-primary hover:text-primary-hover"
          >
            <span className="material-symbols-outlined text-sm block">add</span>
          </button>
        </div>

        {showCreateForm ? (
          <div className="space-y-2 overflow-y-auto">
            <input
              type="text"
              placeholder="Session Title..."
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              className="w-full bg-surface border border-border rounded p-1 text-[11px]"
            />
            <input
              type="text"
              placeholder="Analyst Name..."
              value={analyst}
              onChange={(e) => setAnalyst(e.target.value)}
              className="w-full bg-surface border border-border rounded p-1 text-[11px]"
            />
            <div className="flex justify-end gap-1.5 mt-1">
              <button
                onClick={() => setShowCreateForm(false)}
                className="px-2 py-0.5 border border-border rounded"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                className="px-2 py-0.5 bg-primary text-on-primary rounded"
              >
                Create
              </button>
            </div>
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto space-y-1">
            {investigations.map((inv) => (
              <button
                key={inv.id}
                onClick={() => onSwitch(inv)}
                className={`w-full text-left p-2 rounded border transition-colors flex justify-between items-center ${
                  activeInvestigation?.id === inv.id
                    ? 'border-primary/40 bg-primary/5 text-primary'
                    : 'border-border bg-surface/30 hover:border-border-hover text-on-surface-variant'
                }`}
              >
                <div className="truncate pr-2">
                  <span className="font-bold block truncate">{inv.title}</span>
                  <span className="text-[9px] opacity-60 block truncate">{inv.analyst_name}</span>
                </div>
                <span className="text-[8px] bg-border/40 px-1 py-0.5 rounded">
                  {inv.notes_count} N / {inv.bookmarks_count} B
                </span>
              </button>
            ))}
          </div>
        )}
      </GlassPanel>

      {/* Analyst Notes workspace */}
      <GlassPanel className="p-4 border-border bg-surface-variant/5 flex flex-col flex-1 h-0">
        <span className="font-bold text-secondary border-b border-border pb-2 mb-2 block">
          CASE NOTES ({notes.length})
        </span>

        {activeInvestigation ? (
          <div className="flex flex-col h-full overflow-hidden">
            {/* Notes list */}
            <div className="flex-1 overflow-y-auto space-y-2 pr-1 mb-3">
              {notes.length === 0 ? (
                <div className="text-center py-12 opacity-50">No notes written.</div>
              ) : (
                notes.map((n) => (
                  <div key={n.id} className="p-2 border border-border bg-surface/50 rounded-lg select-text font-mono">
                    <div className="flex justify-between items-center text-[9px] opacity-50 mb-1">
                      <span className="font-bold text-secondary">{n.note_type.toUpperCase()}</span>
                      <span>{new Date(n.created_at).toLocaleTimeString()}</span>
                    </div>
                    <p className="text-[10px] leading-relaxed text-on-surface-variant">{n.content}</p>
                  </div>
                ))
              )}
            </div>

            {/* Note input form */}
            <div className="border-t border-border pt-3 mt-auto space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-[10px] text-on-surface-variant">Write Note</span>
                <select
                  value={noteType}
                  onChange={(e) => setNoteType(e.target.value)}
                  className="bg-surface border border-border rounded text-[10px] px-1.5"
                >
                  <option value="general">General</option>
                  <option value="finding">Finding</option>
                  <option value="question">Question</option>
                  <option value="action">Action</option>
                </select>
              </div>
              <textarea
                placeholder="Record threat notes..."
                value={noteContent}
                onChange={(e) => setNoteContent(e.target.value)}
                className="w-full h-12 bg-surface border border-border rounded p-1.5 focus:outline-none focus:border-secondary text-on-surface text-[10px]"
              />
              <button
                onClick={handleAddNote}
                disabled={!noteContent.trim()}
                className="w-full bg-secondary text-on-secondary py-1 text-[10px] font-bold rounded hover:bg-secondary/90 disabled:opacity-50"
              >
                SAVE NOTE
              </button>
            </div>
          </div>
        ) : (
          <div className="text-center py-20 opacity-55">
            Select or create an investigation session to record notes.
          </div>
        )}
      </GlassPanel>

      {/* Bookmarks */}
      {activeInvestigation && bookmarks.length > 0 && (
        <GlassPanel className="p-4 border-border bg-surface-variant/5 max-h-[150px] overflow-y-auto">
          <span className="font-bold text-success border-b border-border pb-1.5 mb-1.5 block uppercase tracking-wide">
            Bookmarked Items ({bookmarks.length})
          </span>
          <div className="space-y-1">
            {bookmarks.map((b) => (
              <div
                key={b.id}
                className="p-1.5 border border-border bg-surface/30 rounded flex justify-between items-center text-[10px]"
              >
                <div className="truncate pr-2">
                  <span className="font-bold block truncate text-on-surface">{b.label}</span>
                  <span className="text-[9px] text-on-surface-variant opacity-60 block truncate select-text">
                    {b.target_id}
                  </span>
                </div>
                <span className="text-[8px] border border-success/30 text-success bg-success/5 px-1 py-0.5 rounded font-bold uppercase">
                  {b.severity}
                </span>
              </div>
            ))}
          </div>
        </GlassPanel>
      )}
    </div>
  )
}
export default InvestigationSidebar
