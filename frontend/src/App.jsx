import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./context/AuthContext";
import Sidebar from "./components/Sidebar";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import ScanPage from "./pages/ScanPage";
import ProvidersPage from "./pages/ProvidersPage";
import ConnectPage from "./pages/ConnectPage";
import FindingsPage from "./pages/FindingsPage";
import ReportsPage from "./pages/ReportsPage";
import DocsPage from "./pages/DocsPage";
import DeepScanPage from "./pages/DeepScanPage";
import GraphIntelligencePage from "./pages/GraphIntelligencePage";
import RuleEffectivenessPage from "./pages/RuleEffectivenessPage";
import IaC from "./components/IaC";

function ProtectedRoute({ children }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return children;
}

function AppLayout({ children }) {
  return (
    <div className="flex h-screen overflow-hidden bg-slate-900">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">{children}</main>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public routes */}
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/docs" element={<DocsPage />} />
        <Route path="/iac" element={
          
            <AppLayout>
              <IaC />
            </AppLayout>
          
        } />

        {/* Protected routes with sidebar */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <AppLayout><DashboardPage /></AppLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/scan"
          element={
            <ProtectedRoute>
              <AppLayout><ScanPage /></AppLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/providers"
          element={
            <ProtectedRoute>
              <AppLayout><ProvidersPage /></AppLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/connect"
          element={
            <ProtectedRoute>
              <AppLayout><ConnectPage /></AppLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/findings"
          element={
            <ProtectedRoute>
              <AppLayout><FindingsPage /></AppLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/deep-scan"
          element={
            <ProtectedRoute>
              <AppLayout><DeepScanPage /></AppLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/graph-intelligence"
          element={
            <ProtectedRoute>
              <AppLayout><GraphIntelligencePage /></AppLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/rule-effectiveness"
          element={
            <ProtectedRoute>
              <AppLayout><RuleEffectivenessPage /></AppLayout>
            </ProtectedRoute>
          }
        />
        {/* Anomaly detection hidden from nav — backend pipeline preserved */}
        <Route
          path="/reports"
          element={
            <ProtectedRoute>
              <AppLayout><ReportsPage /></AppLayout>
            </ProtectedRoute>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
