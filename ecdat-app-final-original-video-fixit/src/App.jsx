import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext.jsx'
import { ScanProvider } from './context/ScanContext.jsx'
import ProtectedRoute from './components/ProtectedRoute.jsx'
import ErrorBoundary from './components/ErrorBoundary.jsx'
import Home from './pages/Home.jsx'
import ECDATLogin from './ECDATLogin.jsx'
import ResetPassword from './pages/ResetPassword.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Remediator from './pages/Remediator.jsx'
import MoscaTimeline from './pages/MoscaTimeline.jsx'
import ComplianceReports from './pages/ComplianceReports.jsx'
import References from './pages/References.jsx'
import Activity from './pages/Activity.jsx'
import Settings from './pages/Settings.jsx'
import HelpCentre from './pages/HelpCentre.jsx'
import NewsArticle from './pages/NewsArticle.jsx'

export default function App() {
  return (
    <ErrorBoundary>
    <AuthProvider>
      <ScanProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<ECDATLogin />} />
            <Route path="/reset-password" element={<ResetPassword />} />
            <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
            <Route path="/remediator" element={<ProtectedRoute><Remediator /></ProtectedRoute>} />
            <Route path="/mosca-timeline" element={<ProtectedRoute><MoscaTimeline /></ProtectedRoute>} />
            <Route path="/compliance-reports" element={<ProtectedRoute><ComplianceReports /></ProtectedRoute>} />
            <Route path="/references" element={<References />} />
            <Route path="/activity" element={<ProtectedRoute><Activity /></ProtectedRoute>} />
            <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
            <Route path="/help" element={<HelpCentre />} />
            <Route path="/news" element={<NewsArticle />} />
          </Routes>
        </BrowserRouter>
      </ScanProvider>
    </AuthProvider>
    </ErrorBoundary>
  )
}
