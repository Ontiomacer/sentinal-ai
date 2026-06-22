import GlassPanel from '../components/ui/GlassPanel'

const CaseNotesPage = () => {
  return (
    <div className="fade-in">
      <GlassPanel className="p-12 text-center">
        <span className="material-symbols-outlined text-6xl text-on-surface mb-6 block">
          description
        </span>
        <h2 className="font-title-md text-title-md text-on-surface mb-4">
          Investigator Notes
        </h2>
        <p className="text-body-md text-on-surface-variant mb-8 max-w-2xl mx-auto">
          Document findings, hypotheses, and conclusions. Notes support markdown formatting
          and can be categorized by type for organized investigation documentation.
        </p>
        <button className="btn-primary inline-flex px-8 py-3">
          <span className="material-symbols-outlined">add</span>
          CREATE NOTE
        </button>
      </GlassPanel>
    </div>
  )
}

export default CaseNotesPage
