import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useUser } from '@clerk/clerk-react'
import GlassPanel from '../components/ui/GlassPanel'
import ThreatBadge from '../components/ui/ThreatBadge'
import { createCase } from '../services/caseApi'

const CreateCasePage = () => {
  const { user } = useUser()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [formData, setFormData] = useState({
    name: '',
    client_name: '',
    investigator: user?.fullName || user?.username || '',
    description: '',
    severity: 'medium' as 'critical' | 'high' | 'medium' | 'low' | 'info',
    tags: ''
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const tags = formData.tags
        .split(',')
        .map(tag => tag.trim())
        .filter(tag => tag.length > 0)

      const caseData = {
        name: formData.name,
        client_name: formData.client_name || undefined,
        investigator: formData.investigator,
        description: formData.description || undefined,
        severity: formData.severity,
        tags: tags.length > 0 ? tags : undefined
      }

      const newCase = await createCase(caseData)
      navigate(`/cases/${newCase.id}`)
    } catch (err: any) {
      console.error('Failed to create case:', err)
      setError(err.response?.data?.detail || 'Failed to create case')
    } finally {
      setLoading(false)
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    })
  }

  return (
    <div className="container-padding fade-in">
      {/* Hero Section */}
      <section className="mb-12 relative max-w-4xl">
        <div className="flex items-center gap-2 mb-4">
          <ThreatBadge severity="MEDIUM" label="Case Initialization" />
          <span className="text-on-surface-variant font-label-sm text-label-sm opacity-50">
            — FORENSIC INVESTIGATION SETUP
          </span>
        </div>
        <h1 className="font-display-xl text-display-xl tracking-tighter text-on-surface leading-tight mb-6">
          NEW INVESTIGATION
        </h1>
        <p className="font-body-lg text-body-lg text-on-surface-variant max-w-3xl leading-relaxed">
          Initialize a new forensic investigation case. Define scope, assign investigators,
          and establish the investigation framework.
        </p>
      </section>

      {/* Form */}
      <section className="mb-section-gap max-w-4xl">
        <form onSubmit={handleSubmit}>
          <GlassPanel className="p-8">
            {error && (
              <div className="mb-6 p-4 bg-error/10 border border-error/20 rounded">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-error">error</span>
                  <span className="text-error font-body-md">{error}</span>
                </div>
              </div>
            )}

            {/* Case Name */}
            <div className="mb-6">
              <label className="block font-label-sm text-label-sm text-on-surface-variant uppercase mb-2">
                Case Name *
              </label>
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleChange}
                required
                placeholder="Operation Dark Wallet"
                className="w-full px-4 py-3 bg-surface-container border border-white/10 rounded font-body-md text-on-surface placeholder-on-surface-variant/50 focus:outline-none focus:border-secondary transition-colors"
              />
            </div>

            {/* Client Name */}
            <div className="mb-6">
              <label className="block font-label-sm text-label-sm text-on-surface-variant uppercase mb-2">
                Client / Organization
              </label>
              <input
                type="text"
                name="client_name"
                value={formData.client_name}
                onChange={handleChange}
                placeholder="Acme Financial Services"
                className="w-full px-4 py-3 bg-surface-container border border-white/10 rounded font-body-md text-on-surface placeholder-on-surface-variant/50 focus:outline-none focus:border-secondary transition-colors"
              />
            </div>

            {/* Investigator */}
            <div className="mb-6">
              <label className="block font-label-sm text-label-sm text-on-surface-variant uppercase mb-2">
                Lead Investigator *
              </label>
              <input
                type="text"
                name="investigator"
                value={formData.investigator}
                onChange={handleChange}
                required
                placeholder="Jane Doe"
                className="w-full px-4 py-3 bg-surface-container border border-white/10 rounded font-body-md text-on-surface placeholder-on-surface-variant/50 focus:outline-none focus:border-secondary transition-colors"
              />
            </div>

            {/* Severity */}
            <div className="mb-6">
              <label className="block font-label-sm text-label-sm text-on-surface-variant uppercase mb-2">
                Severity Level *
              </label>
              <select
                name="severity"
                value={formData.severity}
                onChange={handleChange}
                required
                className="w-full px-4 py-3 bg-surface-container border border-white/10 rounded font-body-md text-on-surface focus:outline-none focus:border-secondary transition-colors"
              >
                <option value="info">Info</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>

            {/* Description */}
            <div className="mb-6">
              <label className="block font-label-sm text-label-sm text-on-surface-variant uppercase mb-2">
                Investigation Description
              </label>
              <textarea
                name="description"
                value={formData.description}
                onChange={handleChange}
                rows={4}
                placeholder="Suspected banking trojan targeting mobile users. Initial indicators suggest credential harvesting and SMS interception capabilities..."
                className="w-full px-4 py-3 bg-surface-container border border-white/10 rounded font-body-md text-on-surface placeholder-on-surface-variant/50 focus:outline-none focus:border-secondary transition-colors resize-none"
              />
            </div>

            {/* Tags */}
            <div className="mb-8">
              <label className="block font-label-sm text-label-sm text-on-surface-variant uppercase mb-2">
                Tags (comma-separated)
              </label>
              <input
                type="text"
                name="tags"
                value={formData.tags}
                onChange={handleChange}
                placeholder="banking, trojan, mobile, credential-theft"
                className="w-full px-4 py-3 bg-surface-container border border-white/10 rounded font-body-md text-on-surface placeholder-on-surface-variant/50 focus:outline-none focus:border-secondary transition-colors"
              />
              <p className="mt-2 text-label-sm text-on-surface-variant opacity-60">
                Separate tags with commas for categorization and filtering
              </p>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-between pt-6 border-t border-white/5">
              <button
                type="button"
                onClick={() => navigate('/cases')}
                className="btn-secondary px-6 py-3 inline-flex items-center gap-2"
                disabled={loading}
              >
                <span className="material-symbols-outlined">arrow_back</span>
                CANCEL
              </button>

              <button
                type="submit"
                className="btn-primary px-8 py-3 inline-flex items-center gap-2"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <span className="material-symbols-outlined animate-spin">progress_activity</span>
                    INITIALIZING...
                  </>
                ) : (
                  <>
                    <span className="material-symbols-outlined">add</span>
                    CREATE INVESTIGATION
                  </>
                )}
              </button>
            </div>
          </GlassPanel>
        </form>
      </section>

      {/* Info Panel */}
      <section className="max-w-4xl">
        <GlassPanel className="p-6">
          <div className="flex items-start gap-4">
            <span className="material-symbols-outlined text-3xl text-secondary">
              info
            </span>
            <div>
              <h3 className="font-title-md text-title-md text-on-surface mb-2">
                Investigation Workspace
              </h3>
              <p className="text-body-md text-on-surface-variant leading-relaxed">
                Upon creation, a dedicated forensic workspace will be initialized with evidence vaults,
                timeline tracking, entity management, and AI-powered analysis capabilities. All investigation
                artifacts will be organized within an isolated case directory structure.
              </p>
            </div>
          </div>
        </GlassPanel>
      </section>
    </div>
  )
}

export default CreateCasePage
