import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Login } from './components/Login';
import { UserDashboard } from './components/UserDashboard';
import { UploadPage } from './components/UploadPage';
import { AnalysisViewer } from './components/AnalysisViewer';
import { AdminDashboard } from './components/AdminDashboard';
import { ProtectedRoute } from './components/ProtectedRoute';
import { Registro } from './components/Registro';
import '../styles/fonts.css';

export default function App() {
  return (
    <div className="dark">
      <BrowserRouter>
        <Routes>
          {/* RUTA PÚBLICA */}
          <Route path="/" element={<Login />} />
          <Route path="/login" element={<Login />} />
          <Route path="/registro" element={<Registro />} />

          {/* RUTAS PROTEGIDAS (Requieren sesión) */}
          <Route element={<ProtectedRoute />}>
            <Route path="/dashboard" element={<UserDashboard />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/admin" element={<AdminDashboard />} />
            {/* Agrupamos las variantes de análisis */}
            <Route path="/analisis" element={<AnalysisViewer />} />
            <Route path="/analisis/:id" element={<AnalysisViewer />} />
          </Route>

          {/* REDIRECCIÓN GLOBAL: 
              Si la ruta no existe, manda al Login. 
          */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}