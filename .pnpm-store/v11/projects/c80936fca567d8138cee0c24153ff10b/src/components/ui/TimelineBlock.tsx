interface TimelineBlockProps {
  phase: string
  title: string
  timestamp: string
  severity?: 'primary' | 'secondary' | 'error' | 'tertiary'
}

const TimelineBlock = ({ phase, title, timestamp, severity = 'primary' }: TimelineBlockProps) => {
  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case 'primary':
        return 'text-primary'
      case 'secondary':
        return 'text-secondary'
      case 'error':
        return 'text-error border-error/20'
      case 'tertiary':
        return 'text-tertiary border-tertiary/20'
      default:
        return 'text-primary'
    }
  }

  return (
    <div className={`timeline-block ${severity === 'error' || severity === 'tertiary' ? getSeverityColor(severity) : ''}`}>
      <span className={`font-label-sm text-label-sm ${getSeverityColor(severity)} tracking-widest`}>
        {phase}
      </span>
      <p className="text-body-md font-medium text-on-surface">{title}</p>
      <span className="text-on-surface-variant font-label-sm text-label-sm opacity-50">
        {timestamp}
      </span>
    </div>
  )
}

export default TimelineBlock
