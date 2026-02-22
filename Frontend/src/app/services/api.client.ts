import { authService } from './auth.service';

const BASE_URL = 'http://localhost:8000/api';

// src/services/api.client.ts
export const apiClient = async (endpoint: string, options: RequestInit = {}) => {
    const token = authService.getToken();
    
    const headers: Record<string, string> = {
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...((options.headers as Record<string, string>) || {}),
    };
  
    // Solo añadimos JSON si no estamos enviando un archivo (FormData)
    if (!(options.body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
    }
  
    const response = await fetch(`http://localhost:8000/api${endpoint}`, {
      ...options,
      headers,
    });
  
    if (response.status === 401) {
      authService.logout();
      return Promise.reject('Unauthorized');
    }

    if (response.status === 403) {
      return Promise.reject('Forbidden');
    }
  
    return response;
  };