import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import useAuthStore from './store/authStore';
import Layout from './components/Layout';
import LoginPage from './pages/Login';
import DashboardPage from './pages/Dashboard';
import AlertsPage from './pages/Alerts';
import AlertDetailPage from './pages/AlertDetail';
import IncidentsPage from './pages/Incidents';
import IncidentDetailPage from './pages/IncidentDetail';
import AssetsPage from './pages/Assets';
import HuntPage from './pages/Hunt';
import RulesPage from './pages/Rules';
import SOARPage from './pages/SOAR';
import ThreatIntelPage from './pages/ThreatIntel';
import VulnerabilitiesPage from './pages/Vulnerabilities';
import MitreMatrixPage from './pages/MitreMatrix';
import TopologyPage from './pages/Topology';
import ReportsPage from './pages/Reports';
import AdminPage from './pages/Admin';

function PrivateRoute({ children }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  return isAuthenticated ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#131c2e',
            color: '#e8edf5',
            border: '1px solid #1e2d45',
            borderRadius: '10px',
            fontSize: '13px',
          },
          success: { iconTheme: { primary: '#10b981', secondary: '#0a0d14' } },
          error:   { iconTheme: { primary: '#ff3b5c', secondary: '#0a0d14' } },
        }}
      />
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/"
          element={
            <PrivateRoute>
              <Layout />
            </PrivateRoute>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard"         element={<DashboardPage />} />
          <Route path="alerts"            element={<AlertsPage />} />
          <Route path="alerts/:id"        element={<AlertDetailPage />} />
          <Route path="incidents"         element={<IncidentsPage />} />
          <Route path="incidents/:id"     element={<IncidentDetailPage />} />
          <Route path="assets"            element={<AssetsPage />} />
          <Route path="hunt"              element={<HuntPage />} />
          <Route path="mitre"             element={<MitreMatrixPage />} />
          <Route path="topology"          element={<TopologyPage />} />
          <Route path="rules"             element={<RulesPage />} />
          <Route path="soar"              element={<SOARPage />} />
          <Route path="threat-intel"      element={<ThreatIntelPage />} />
          <Route path="vulnerabilities"   element={<VulnerabilitiesPage />} />
          <Route path="reports"           element={<ReportsPage />} />
          <Route path="admin"             element={<AdminPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
