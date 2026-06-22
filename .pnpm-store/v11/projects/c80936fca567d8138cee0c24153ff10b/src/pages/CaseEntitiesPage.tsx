import { useState, useEffect } from 'react'
import { useOutletContext } from 'react-router-dom'
import GlassPanel from '../components/ui/GlassPanel'
import { CaseResponse, listEntities, Entity } from '../services/caseApi'

interface CaseContextType {
  caseData: CaseResponse
  refreshCase: () => void
}

const CaseEntitiesPage = () => {
  const { caseData } = useOutletContext<CaseContextType>()
  const [entities, setEntities] = useState<Entity[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchEntities()
  }, [caseData.id])

  const fetchEntities = async () => {
    try {
      setLoading(true)
      const data = await listEntities(caseData.id)
      setEntities(data)
    } catch (error) {
      console.error('Failed to fetch entities:', error)
    } finally {
      setLoading(false)
    }
  }

  const getEntityIcon = (type: string) => {
    switch (type) {
      case 'domain': return 'language'
      case 'url': return 'link'
      case 'wallet': return 'account_balance_wallet'
      case 'person': return 'person'
      case 'organization': return 'business'
      case 'ip_address': return 'router'
      case 'email': return 'email'
      case 'phone': return 'phone'
      case 'apk': return 'android'
      default: return 'label'
    }
  }

  if (loading) {
    return (
      <div className="fade-in">
        <GlassPanel className="p-12 text-center">
          <span className="material-symbols-outlined text-6xl text-tertiary mb-4 block animate-pulse">
            hub
          </span>
          <p className="text-body-md text-on-surface-variant">Loading entities...</p>
        </GlassPanel>
      </div>
    )
  }

  return (
    <div className="fade-in">
      {entities.length === 0 ? (
        <GlassPanel className="p-12 text-center">
          <span className="material-symbols-outlined text-6xl text-tertiary mb-6 block">
            hub
          </span>
          <h2 className="font-title-md text-title-md text-on-surface mb-4">
            Entity Tracking
          </h2>
          <p className="text-body-md text-on-surface-variant mb-8 max-w-2xl mx-auto">
            Track forensic entities including domains, URLs, wallets, actors, and infrastructure.
            Build relationship maps and identify patterns across the investigation.
          </p>
          <button className="btn-primary inline-flex px-8 py-3">
            <span className="material-symbols-outlined">add</span>
            ADD ENTITY
          </button>
        </GlassPanel>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-gutter">
          {entities.map((entity) => (
            <GlassPanel key={entity.id} className="p-6 hover:border-tertiary/60 transition-all">
              <div className="flex items-start gap-3 mb-4">
                <span className="material-symbols-outlined text-2xl text-tertiary">
                  {getEntityIcon(entity.entity_type)}
                </span>
                <div className="flex-1">
                  <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-1">
                    {entity.entity_type.replace('_', ' ')}
                  </span>
                  <h3 className="font-title-sm text-title-sm text-on-surface mb-1">
                    {entity.name}
                  </h3>
                </div>
                {entity.risk_score !== undefined && (
                  <span className={`font-title-sm text-title-sm ${
                    entity.risk_score >= 70 ? 'text-error' :
                    entity.risk_score >= 50 ? 'text-secondary' :
                    'text-primary'
                  }`}>
                    {entity.risk_score}
                  </span>
                )}
              </div>
              <p className="font-mono text-body-md text-on-surface mb-3 break-all">
                {entity.value}
              </p>
              {entity.description && (
                <p className="text-body-md text-on-surface-variant">
                  {entity.description}
                </p>
              )}
            </GlassPanel>
          ))}
        </div>
      )}
    </div>
  )
}

export default CaseEntitiesPage
