// src/app/services/auth.service.ts
export const authService = {
    async login(credentials: { username: string; password: string; token?: string }) {
      const response = await fetch('http://localhost:8000/api/login/', { // Ajusta a tu URL de Django
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });
  
      if (!response.ok) {
        throw new Error('Credenciales inválidas');
      }
  
      const data = await response.json();
      
      // Almacenamos el token para futuras peticiones
      localStorage.setItem('access_token', data.access);
      localStorage.setItem('refresh_token', data.refresh);
      
      return data;
    },
  
    logout() {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      window.location.href = '/login';
    },
  
    getToken() {
      return localStorage.getItem('access_token');
    }
  };