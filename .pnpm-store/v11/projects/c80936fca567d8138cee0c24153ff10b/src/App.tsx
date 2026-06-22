import { BrowserRouter as Router, Routes, Route, Outlet } from 'react-router-dom'
import Layout from './components/layout/Layout'
import LandingPage from './pages/LandingPage'
import CaseDashboardPage from './pages/CaseDashboardPage'
import CreateCasePage from './pages/CreateCasePage'
import CaseWorkspacePage from './pages/CaseWorkspacePage'
import CaseOverviewPage from './pages/CaseOverviewPage'
import CaseEvidencePage from './pages/CaseEvidencePage'
import CaseFilesPage from './pages/CaseFilesPage'
import CaseTimelinePage from './pages/CaseTimelinePage'
import CaseEntitiesPage from './pages/CaseEntitiesPage'
import CaseNotesPage from './pages/CaseNotesPage'
import CaseReportsPage from './pages/CaseReportsPage'
import CaseTriagePage from './pages/CaseTriagePage'
import CodeAnalysisPage from './pages/CodeAnalysisPage'
import UploadPage from './pages/UploadPage'
import ScanAnalysisPage from './pages/ScanAnalysisPage'
import ScanHistoryPage from './pages/ScanHistoryPage'
import AIBriefingPage from './pages/AIBriefingPage'
import NeuralLabPage from './pages/NeuralLabPage'
import MCPMarketplacePage from './pages/MCPMarketplacePage'
import CLIReferencePage from './pages/CLIReferencePage'
import ThreatOperationsPage from './pages/ThreatOperationsPage'
import DeviceLabPageV4 from './pages/DeviceLabPageV4'
import AppAnalysisPage from './pages/AppAnalysisPage'

function App() {
  return (
    <Router
      future={{
        v7_startTransition: true,
        v7_relativeSplatPath: true
      }}
    >
      <Routes>
        {/* Landing Page - No standard layout */}
        <Route path="/" element={<LandingPage />} />

        {/* All other pages - Use standard Layout */}
        <Route element={<Layout><Outlet /></Layout>}>
          {/* Case Management Routes */}
          <Route path="/cases" element={<CaseDashboardPage />} />
          <Route path="/cases/new" element={<CreateCasePage />} />
          
          {/* Case Workspace with Nested Routes */}
          <Route path="/cases/:caseId" element={<CaseWorkspacePage />}>
            <Route index element={<CaseOverviewPage />} />
            <Route path="evidence" element={<CaseEvidencePage />} />
            <Route path="files" element={<CaseFilesPage />} />
            <Route path="timeline" element={<CaseTimelinePage />} />
            <Route path="entities" element={<CaseEntitiesPage />} />
            <Route path="notes" element={<CaseNotesPage />} />
            <Route path="code-analysis" element={<CodeAnalysisPage />} />
            <Route path="neural-lab" element={<NeuralLabPage />} />
            <Route path="reports" element={<CaseReportsPage />} />
            <Route path="triage" element={<CaseTriagePage />} />
            <Route path="threat-ops" element={<ThreatOperationsPage />} />
          </Route>

          {/* Legacy Routes (for backward compatibility) */}
          <Route path="/upload" element={<UploadPage />} />
          <Route path="/scan/:scanId" element={<ScanAnalysisPage />} />
          <Route path="/history" element={<ScanHistoryPage />} />
          <Route path="/briefing/:scanId" element={<AIBriefingPage />} />
          <Route path="/neural-lab" element={<NeuralLabPage />} />
          <Route path="/neural-lab/:scanId" element={<NeuralLabPage />} />
          <Route path="/mcp" element={<MCPMarketplacePage />} />
          <Route path="/mcp/marketplace" element={<MCPMarketplacePage />} />
          <Route path="/cli" element={<CLIReferencePage />} />
          <Route path="/threat-ops" element={<ThreatOperationsPage />} />
          <Route path="/threat-ops/:evidenceId" element={<ThreatOperationsPage />} />
          <Route path="/device-lab" element={<DeviceLabPageV4 />} />
          <Route path="/device-lab/:caseId" element={<DeviceLabPageV4 />} />
          <Route path="/app-analysis/:analysisId" element={<AppAnalysisPage />} />
          <Route path="/app-analysis" element={<AppAnalysisPage />} />
        </Route>
      </Routes>
    </Router>
  )
}

export default App
