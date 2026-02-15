import { Navigate, Outlet } from 'react-router-dom';
import { authService } from '../services/auth.service';

export const ProtectedRoute = () => {
  const isAuthenticated = !!authService.getToken();

  if (!isAuthenticated) {
    // Redirige al login si no hay sesión
    return <Navigate to="/login" replace />;
  }

  // Si hay sesión, renderiza los componentes hijos
  return <Outlet />;
};