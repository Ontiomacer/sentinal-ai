interface ThreatBadgeProps {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  label: string
  className?: string
}

const ThreatBadge = ({ severity, label, className = '' }: ThreatBadgeProps) => {
  const severityClasses = {
    CRITICAL: 'threat-badge-critical',
    HIGH: 'threat-badge-high',
    MEDIUM: 'threat-badge-medium',
    LOW: 'threat-badge-low',
  }

  return (
    <span className={`${severityClasses[severity]} ${className}`}>
      {label}
    </span>
  )
}

export default ThreatBadge
