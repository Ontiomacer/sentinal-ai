import GlassPanel from './GlassPanel'

interface FeedItem {
  timestamp: string
  message: string
  severity: 'primary' | 'secondary' | 'tertiary'
}

interface IntelligenceFeedProps {
  items: FeedItem[]
  title?: string
}

const IntelligenceFeed = ({ items, title = 'Intelligence Feed' }: IntelligenceFeedProps) => {
  const getBorderColor = (severity: string) => {
    switch (severity) {
      case 'primary':
        return 'border-primary'
      case 'secondary':
        return 'border-secondary'
      case 'tertiary':
        return 'border-tertiary'
      default:
        return 'border-primary'
    }
  }

  return (
    <GlassPanel className="p-6">
      <h3 className="font-title-md text-title-md mb-4 text-on-surface">{title}</h3>
      <div className="space-y-4">
        {items.map((item, index) => (
          <div key={index} className={`intel-feed-item ${getBorderColor(item.severity)}`}>
            <span className="block font-label-sm text-label-sm text-on-surface-variant opacity-50">
              {item.timestamp}
            </span>
            <p className="text-body-md text-on-surface">{item.message}</p>
          </div>
        ))}
      </div>
    </GlassPanel>
  )
}

export default IntelligenceFeed
