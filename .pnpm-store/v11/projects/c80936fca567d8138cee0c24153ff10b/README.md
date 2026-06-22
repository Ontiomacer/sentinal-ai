# Sentinel AI - Frontend

A cinematic malware intelligence platform built with React, TypeScript, and Vite.

## Design Philosophy

This frontend embodies an **editorial cyber intelligence** aesthetic:
- Calm and atmospheric (not a noisy SOC dashboard)
- Cinematic spacing and typography
- Minimal and premium feel
- AI-assisted threat cognition
- Investigation-focused flow

## Tech Stack

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool
- **TailwindCSS** - Styling (custom design system)
- **React Router** - Navigation
- **Axios** - API communication
- **Framer Motion** - Subtle animations

## Project Structure

```
frontend/
├── src/
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Layout.tsx          # Main layout wrapper
│   │   │   ├── Header.tsx          # Top navigation
│   │   │   └── Footer.tsx          # Footer
│   │   └── ui/
│   │       ├── GlassPanel.tsx      # Glassmorphism container
│   │       ├── ThreatBadge.tsx     # Severity indicators
│   │       ├── NeuralTerminal.tsx  # Terminal-style logs
│   │       ├── NeuralVisualization.tsx  # Central viz area
│   │       ├── IntelligenceFeed.tsx     # News feed component
│   │       └── TimelineBlock.tsx   # Attack timeline blocks
│   ├── pages/
│   │   ├── UploadPage.tsx          # APK upload interface
│   │   ├── ScanAnalysisPage.tsx    # Scan results view
│   │   ├── ScanHistoryPage.tsx     # Historical scans
│   │   └── AIBriefingPage.tsx      # Detailed threat briefing
│   ├── services/
│   │   └── api.ts                  # API client & types
│   ├── App.tsx                     # Root component with routing
│   ├── main.tsx                    # Entry point
│   └── index.css                   # Global styles & design system
├── index.html
├── tailwind.config.js              # Custom design tokens
├── vite.config.ts
└── package.json
```

## Design System

### Colors

The palette is anchored in **Deep Midnight** with glassmorphism effects:

- **Background**: `#091324` - Deep midnight canvas
- **Surface**: `#162031` - Glass panel base
- **Primary**: `#c5c6cb` - Slate for text
- **Secondary**: `#a6c8ff` - Electric blue for actions
- **Tertiary**: `#51df8e` - Emerald for success states
- **Error**: `#ffb4ab` - Soft red for threats

### Typography

- **Display XL**: 72px/800 weight - Hero headlines
- **Headline LG**: 48px/700 weight - Section titles
- **Title MD**: 24px/600 weight - Card headers
- **Body LG**: 18px/400 weight - Editorial copy
- **Body MD**: 16px/400 weight - Standard text
- **Label SM**: 12px/500 weight - Metadata (Geist Mono)

### Spacing

- **Container Padding**: 64px desktop, 24px mobile
- **Section Gap**: 120px vertical rhythm
- **Gutter**: 24px between elements
- **Base**: 8px grid system

### Components

#### Glass Panel
```tsx
<GlassPanel className="p-6" glow>
  {children}
</GlassPanel>
```

#### Threat Badge
```tsx
<ThreatBadge severity="CRITICAL" label="Threat Detected" />
```

#### Neural Terminal
```tsx
<NeuralTerminal 
  logs={[
    { timestamp: '09:21:44', type: 'success', message: 'SCAN COMPLETE' }
  ]} 
/>
```

## Setup

### Prerequisites

- Node.js 18+ and npm
- Backend API running on `http://localhost:8000`

### Installation

```bash
cd frontend
npm install
```

### Environment Configuration

```bash
cp .env.example .env
```

Edit `.env` if your backend runs on a different URL:
```
VITE_API_URL=http://localhost:8000
```

### Development

```bash
npm run dev
```

Frontend will be available at `http://localhost:3000`

### Build for Production

```bash
npm run build
```

Output will be in `dist/` directory.

### Preview Production Build

```bash
npm run preview
```

## API Integration

The frontend communicates with the FastAPI backend via `/api/v1` endpoints:

### Upload APK
```typescript
import { uploadAPK } from '@/services/api'

const response = await uploadAPK(file)
// Returns: { scan_id, sha256, filename, status, analysis_result }
```

### Get Scan Results
```typescript
import { getScan } from '@/services/api'

const scan = await getScan(scanId)
// Returns: Full scan data with risk assessment
```

## Pages

### 1. Upload Page (`/`)
- Drag & drop APK upload
- File validation
- Upload progress
- Information cards

### 2. Scan Analysis (`/scan/:scanId`)
- Neural visualization
- Real-time terminal logs
- Risk assessment display
- Package information
- Security findings

### 3. Scan History (`/history`)
- List of all scans
- Filter by severity
- Threat statistics
- Quick access to past analyses

### 4. AI Briefing (`/briefing/:scanId`)
- Executive summary
- Threat indicators
- Permission analysis
- Attack timeline
- Tactical recommendations

## Styling Guidelines

### DO:
- Use glass-panel for containers
- Maintain generous spacing (section-gap, gutter)
- Use font-label-sm for metadata
- Apply subtle hover effects (border-secondary/40)
- Keep animations minimal (300ms transitions)

### DON'T:
- Add bright colors or gradients
- Use heavy shadows
- Create busy layouts
- Add unnecessary animations
- Break the 8px grid system

## Key Features

### Glassmorphism
All panels use backdrop blur and subtle borders:
```css
.glass-panel {
  background: rgba(22, 32, 49, 0.4);
  backdrop-filter: blur(24px);
  border: 1px solid rgba(255, 255, 255, 0.08);
}
```

### Neural Glow
Subtle glow effect for emphasis:
```css
.neural-glow {
  box-shadow: 0 0 40px -10px rgba(197, 198, 203, 0.2);
}
```

### Scanline Effect
Terminal-style scanline animation:
```css
.scanline {
  background: linear-gradient(to bottom, transparent 50%, rgba(166, 200, 255, 0.02) 50%);
  background-size: 100% 4px;
}
```

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+

Requires support for:
- CSS backdrop-filter
- CSS Grid
- ES2020 features

## Performance

- Code splitting by route
- Lazy loading for heavy components
- Optimized bundle size (~200KB gzipped)
- Fast refresh in development

## Accessibility

- Semantic HTML
- ARIA labels where needed
- Keyboard navigation support
- Focus indicators
- Color contrast compliance (WCAG AA)

## Contributing

When adding new components:
1. Follow the design system tokens
2. Use TypeScript for type safety
3. Keep components focused and reusable
4. Maintain the editorial aesthetic
5. Test with real API data

## Troubleshooting

### Backend Connection Issues
- Ensure backend is running on port 8000
- Check CORS configuration in FastAPI
- Verify `.env` file has correct API URL

### Build Errors
- Clear `node_modules` and reinstall
- Check Node.js version (18+)
- Verify all dependencies are installed

### Styling Issues
- Ensure Tailwind is processing correctly
- Check custom classes in `index.css`
- Verify font imports in `index.html`

## License

Part of the Sentinel AI APK Analysis Platform.
