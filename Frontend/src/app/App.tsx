import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Login } from './components/Login';
import { UserDashboard } from './components/UserDashboard';
import { UploadPage } from './components/UploadPage';
import { AnalysisViewer } from './components/AnalysisViewer';
import { AdminDashboard } from './components/AdminDashboard';
import '../styles/fonts.css';

export default function App() {
  return (
    <div className="dark">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Login />} />
          <Route path="/dashboard" element={<UserDashboard />} />
          <Route path="/upload" element={<UploadPage />} />
          <Route path="/analysis" element={<AnalysisViewer />} />
          <Route path="/admin" element={<AdminDashboard />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}
