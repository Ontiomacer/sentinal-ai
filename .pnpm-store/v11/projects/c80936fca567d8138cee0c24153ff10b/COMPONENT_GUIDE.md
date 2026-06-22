# Sentinel AI - Component Guide

A comprehensive guide to all reusable components in the Sentinel AI frontend.

---

## Layout Components

### Layout
**File**: `src/components/layout/Layout.tsx`

Main wrapper component that provides consistent structure across all pages.

```tsx
import Layout from '@/components/layout/Layout'

<Layout>
  <YourPageContent />
</Layout>
```

**Features:**
- Fixed header
- Main content area with proper padding
- Footer
- Consistent background and text colors

---

### Header
**File**: `src/components/layout/Header.tsx`

Top navigation bar with glassmorphism effect.

**Features:**
- Logo/brand name
- Navigation links with active states
- Search input (desktop only)
- Notification and account icons
- Responsive design

**Active State:**
Links automatically highlight based on current route using React Router.

---

### Footer
**File**: `src/components/layout/Footer.tsx`

Bottom footer with links and system status.

**Features:**
- Brand name
- Copyright notice
- Footer links
- System status indicator with pulse animation

---

## UI Components

### GlassPanel
**File**: `src/components/ui/GlassPanel.tsx`

Core container component with glassmorphism effect.

```tsx
import GlassPanel from '@/components/ui/GlassPanel'

// Basic usage
<GlassPanel className="p-6">
  <h3>Content</h3>
</GlassPanel>

// With neural glow
<GlassPanel className="p-6" glow>
  <h3>Important content</h3>
</GlassPanel>
```

**Props:**
- `children`: ReactNode - Content to display
- `className?`: string - Additional Tailwind classes
- `glow?`: boolean - Enable neural glow effect

**Styling:**
- Semi-transparent background
- 24px backdrop blur
- 1px white border at 8% opacity
- Optional soft glow shadow

**Use Cases:**
- Cards
- Panels
- Modals
- Information containers

---

### ThreatBadge
**File**: `src/components/ui/ThreatBadge.tsx`

Severity indicator badge with color coding.

```tsx
import ThreatBadge from '@/components/ui/ThreatBadge'

<ThreatBadge severity="CRITICAL" label="Critical Threat Detected" />
<ThreatBadge severity="HIGH" label="High Risk" />
<ThreatBadge severity="MEDIUM" label="Medium Risk" />
<ThreatBadge severity="LOW" label="Low Risk" />
```

**Props:**
- `severity`: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' - Threat level
- `label`: string - Badge text
- `className?`: string - Additional classes

**Color Mapping:**
- **CRITICAL**: Red border, red text, red background (10% opacity)
- **HIGH**: Blue border, blue text, blue background (10% opacity)
- **MEDIUM**: Gray border, gray text, gray background (10% opacity)
- **LOW**: Green border, green text, green background (10% opacity)

**Styling:**
- 2px left border accent
- Uppercase text
- Monospace font (Geist Mono)
- Letter spacing: 0.05em

---

### NeuralTerminal
**File**: `src/components/ui/NeuralTerminal.tsx`

Terminal-style log viewer with auto-scroll and pulsing effect.

```tsx
import NeuralTerminal from '@/components/ui/NeuralTerminal'

const logs = [
  { 
    timestamp: '09:21:44', 
    type: 'success', 
    message: 'INITIALIZING NEURAL SCAN...' 
  },
  { 
    timestamp: '', 
    type: 'info', 
    message: '> Loading heuristic engine...' 
  },
  { 
    timestamp: '09:21:46', 
    type: 'warning', 
    message: 'PATTERN MATCH FOUND' 
  },
  { 
    timestamp: '09:21:48', 
    type: 'error', 
    message: '[!] ALERT: MALICIOUS CALL DETECTED' 
  }
]

<NeuralTerminal 
  logs={logs} 
  title="Neural Analysis Logs"
  height="h-[600px]"
/>
```

**Props:**
- `logs`: TerminalLog[] - Array of log entries
- `title?`: string - Terminal header title (default: "Neural Analysis Logs")
- `height?`: string - Tailwind height class (default: "h-[600px]")

**TerminalLog Interface:**
```typescript
interface TerminalLog {
  timestamp: string    // e.g., "09:21:44" or empty
  type: 'success' | 'info' | 'warning' | 'error'
  message: string
}
```

**Color Coding:**
- **success**: Green (tertiary color)
- **info**: Gray (on-surface-variant)
- **warning**: Blue (secondary color)
- **error**: Red (error color)

**Features:**
- Auto-scroll to bottom on new logs
- Subtle pulsing animation (opacity 1 ↔ 0.8)
- Custom scrollbar styling
- Terminal window controls (3 colored dots)
- Blinking cursor at end
- Dark background with glassmorphism

---

### NeuralVisualization
**File**: `src/components/ui/NeuralVisualization.tsx`

Central visualization area with overlays for confidence, tags, and insights.

```tsx
import NeuralVisualization from '@/components/ui/NeuralVisualization'

<NeuralVisualization
  confidence={99.82}
  tags={['SMS_EXFIL', 'CAM_INJECT', 'PERSISTENCE']}
  insights={[
    {
      title: 'Core Logic',
      description: 'Dynamic link library injection detected in system process space.'
    },
    {
      title: 'Lateral Movement',
      description: 'Scanning for local network MQTT brokers for data tunneling.'
    },
    {
      title: 'Persistence',
      description: 'Obfuscated crontab modification targeting system boot cycles.'
    }
  ]}
>
  {/* Optional: Custom visualization content */}
  <img src="neural-viz.png" alt="Neural network" />
</NeuralVisualization>
```

**Props:**
- `children?`: ReactNode - Custom visualization content
- `confidence?`: number - Confidence percentage (0-100)
- `tags?`: string[] - Threat tags to display
- `insights?`: Array<{title: string, description: string}> - Analysis insights

**Features:**
- Aspect ratio: 16:9
- Glassmorphism with neural glow
- Scanline animation overlay
- Confidence score display (top-left)
- Threat tags (top-right)
- Insights grid (bottom, 3 columns)
- Background gradient placeholder

**Layout:**
- Top: Confidence + Tags
- Bottom: Insights (3-column grid)
- Center: Custom content or gradient

---

### IntelligenceFeed
**File**: `src/components/ui/IntelligenceFeed.tsx`

News feed-style component for displaying intelligence updates.

```tsx
import IntelligenceFeed from '@/components/ui/IntelligenceFeed'

const items = [
  {
    timestamp: '14 MIN AGO',
    message: 'New variant detected in Brazil region.',
    severity: 'primary'
  },
  {
    timestamp: '1 HOUR AGO',
    message: 'C2 Server blacklisted by Neural Lab.',
    severity: 'secondary'
  },
  {
    timestamp: '3 HOURS AGO',
    message: 'Threat intelligence sync completed.',
    severity: 'tertiary'
  }
]

<IntelligenceFeed 
  items={items} 
  title="Intelligence Feed"
/>
```

**Props:**
- `items`: FeedItem[] - Array of feed items
- `title?`: string - Feed title (default: "Intelligence Feed")

**FeedItem Interface:**
```typescript
interface FeedItem {
  timestamp: string
  message: string
  severity: 'primary' | 'secondary' | 'tertiary'
}
```

**Styling:**
- 2px left border (color based on severity)
- Uppercase timestamp in small font
- Hover effect: border changes to secondary color
- Smooth transitions

---

### TimelineBlock
**File**: `src/components/ui/TimelineBlock.tsx`

Attack timeline phase block with hover effects.

```tsx
import TimelineBlock from '@/components/ui/TimelineBlock'

<TimelineBlock
  phase="PHASE 01: INGRESS"
  title="Lure distributed via SMS phishing link."
  timestamp="TIMESTAMP: T-0.00s"
  severity="primary"
/>

<TimelineBlock
  phase="PHASE 03: EXECUTION"
  title="Native library dynamic load attempted."
  timestamp="TIMESTAMP: T+2.1s"
  severity="error"
/>
```

**Props:**
- `phase`: string - Phase label (e.g., "PHASE 01: INGRESS")
- `title`: string - Phase description
- `timestamp`: string - Timestamp label
- `severity?`: 'primary' | 'secondary' | 'error' | 'tertiary' - Color theme

**Features:**
- Glassmorphism panel
- Hover: Scale up (1.02x) + border color change
- Color-coded phase labels
- Smooth transitions (300ms)

**Use Case:**
Display attack timeline in a grid with connector line between blocks.

---

## Styling Utilities

### Custom CSS Classes

Defined in `src/index.css`:

#### Glass Panel
```css
.glass-panel {
  @apply bg-surface-container/40 backdrop-blur-lg border border-white/8;
}
```

#### Neural Glow
```css
.neural-glow {
  box-shadow: 0 0 40px -10px rgba(197, 198, 203, 0.2);
}
```

#### Scanline Effect
```css
.scanline {
  background: linear-gradient(to bottom, transparent 50%, rgba(166, 200, 255, 0.02) 50%);
  background-size: 100% 4px;
}
```

#### Threat Badges
```css
.threat-badge-critical {
  @apply threat-badge border-error bg-error/10 text-error;
}

.threat-badge-high {
  @apply threat-badge border-secondary bg-secondary/10 text-secondary;
}

.threat-badge-medium {
  @apply threat-badge border-primary bg-primary/10 text-primary;
}

.threat-badge-low {
  @apply threat-badge border-tertiary bg-tertiary/10 text-tertiary;
}
```

#### Button Styles
```css
.btn-primary {
  @apply w-full py-3 bg-secondary text-on-secondary font-bold rounded 
         hover:opacity-90 transition-all flex items-center justify-center gap-2;
}

.btn-secondary {
  @apply glass-panel px-4 py-2 rounded hover:border-secondary/40 
         transition-all duration-300;
}
```

---

## Typography Classes

From `tailwind.config.js`:

```tsx
// Display (Hero Headlines)
<h1 className="font-display-xl text-display-xl">
  SENTINEL AI
</h1>

// Headline (Section Titles)
<h2 className="font-headline-lg text-headline-lg">
  THREAT ANALYSIS
</h2>

// Title (Card Headers)
<h3 className="font-title-md text-title-md">
  Risk Assessment
</h3>

// Body Large (Editorial Copy)
<p className="font-body-lg text-body-lg">
  Comprehensive analysis...
</p>

// Body Medium (Standard Text)
<p className="font-body-md text-body-md">
  Standard content...
</p>

// Label Small (Metadata)
<span className="font-label-sm text-label-sm">
  SCAN ID: ABC123
</span>
```

---

## Color Classes

### Surface Colors
```tsx
bg-background           // #091324 - Main background
bg-surface              // #091324 - Surface base
bg-surface-container    // #162031 - Container
bg-surface-container-low      // #111c2d
bg-surface-container-high     // #202a3c
bg-surface-container-highest  // #2b3548
```

### Text Colors
```tsx
text-on-surface         // #d9e3fb - Primary text
text-on-surface-variant // #c6c6ca - Secondary text
text-primary            // #c5c6cb - Accent text
text-secondary          // #a6c8ff - Blue accent
text-tertiary           // #51df8e - Green accent
text-error              // #ffb4ab - Red accent
```

### Border Colors
```tsx
border-white/10         // Subtle borders
border-white/8          // Glass panel borders
border-outline          // #8f9195
border-outline-variant  // #45474a
border-secondary/40     // Hover states
```

---

## Spacing Classes

```tsx
// Container Padding
px-container-padding-desktop  // 64px on desktop
px-container-padding-mobile   // 24px on mobile

// Section Gap
mb-section-gap                // 120px vertical spacing

// Gutter
gap-gutter                    // 24px between elements

// Base
gap-base                      // 8px minimal spacing
```

---

## Animation Classes

```tsx
// Fade In
className="fade-in"

// Status Pulse
className="status-pulse"

// Spin (for loading)
className="animate-spin"

// Pulse (for status indicators)
className="animate-pulse"
```

---

## Material Icons

Include in any component:

```tsx
<span className="material-symbols-outlined">
  security
</span>

<span className="material-symbols-outlined text-error">
  warning
</span>

<span className="material-symbols-outlined text-3xl">
  upload_file
</span>
```

**Common Icons:**
- `security` - Shield
- `warning` - Alert
- `error` - Error
- `upload_file` - Upload
- `description` - Document
- `psychology` - AI/Brain
- `shield` - Protection
- `speed` - Performance
- `notifications` - Bell
- `account_circle` - User
- `arrow_forward` - Right arrow
- `arrow_back` - Left arrow
- `progress_activity` - Loading spinner

---

## Best Practices

### DO:
✅ Use GlassPanel for all containers  
✅ Apply generous spacing (section-gap, gutter)  
✅ Use font-label-sm for metadata  
✅ Keep animations subtle (300ms)  
✅ Maintain 8px grid alignment  
✅ Use ThreatBadge for severity indicators  
✅ Apply hover effects with border-secondary/40  

### DON'T:
❌ Add bright colors or gradients  
❌ Use heavy drop shadows  
❌ Create busy layouts  
❌ Add flashy animations  
❌ Break the typography hierarchy  
❌ Use non-design-system colors  

---

## Component Composition Examples

### Card with Header and Content
```tsx
<GlassPanel className="p-6">
  <h3 className="font-title-md text-title-md mb-4 text-on-surface">
    Risk Assessment
  </h3>
  <div className="space-y-3">
    <p className="text-body-md text-on-surface-variant">
      Content here...
    </p>
  </div>
</GlassPanel>
```

### Stat Display
```tsx
<GlassPanel className="p-6">
  <span className="font-label-sm text-label-sm text-on-surface-variant uppercase block mb-2">
    Risk Score
  </span>
  <span className="font-display-xl text-title-md text-error">
    85/100
  </span>
</GlassPanel>
```

### List with Icons
```tsx
<GlassPanel className="p-6">
  <div className="space-y-3">
    {items.map((item, i) => (
      <div key={i} className="flex items-start gap-3">
        <span className="material-symbols-outlined text-error">
          warning
        </span>
        <p className="text-body-md text-on-surface">{item}</p>
      </div>
    ))}
  </div>
</GlassPanel>
```

---

## Responsive Design

All components are responsive by default:

```tsx
// Mobile-first approach
<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-gutter">
  {/* Stacks on mobile, 2 cols on tablet, 3 cols on desktop */}
</div>

// Hide on mobile
<div className="hidden md:block">
  {/* Only visible on tablet and up */}
</div>

// Container padding
<div className="px-container-padding-mobile md:px-container-padding-desktop">
  {/* 24px on mobile, 64px on desktop */}
</div>
```

---

This component guide provides everything you need to build new features while maintaining the Sentinel AI design language.
