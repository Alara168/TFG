import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, User, Loader2 } from 'lucide-react';
import { authService } from '../services/auth.service';

export function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      // Llamada real al servicio de autenticación
      await authService.login({ username, password });
      
      // Si el login es exitoso, navegamos al dashboard
      navigate('/dashboard');
    } catch (err: any) {
      // Si falla, mostramos el error en la interfaz
      setError(err.message || 'Error de conexión con el servidor');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background relative overflow-hidden">
      {/* Efecto de fondo: lluvia de código binario */}
      <div className="absolute inset-0 opacity-10 pointer-events-none">
        <div className="font-mono text-[#00FF41] text-xs leading-tight overflow-hidden h-full">
          {Array.from({ length: 50 }).map((_, i) => (
            <div key={i} className="animate-pulse" style={{ animationDelay: `${i * 0.1}s` }}>
              {Array.from({ length: 120 }).map(() => Math.random() > 0.5 ? '1' : '0').join('')}
            </div>
          ))}
        </div>
      </div>

      <div className="w-full max-w-md px-6 relative z-10">
        <div className="bg-card border border-border rounded-lg p-8 shadow-2xl">
          {/* Encabezado */}
          <div className="flex items-center justify-center mb-8">
            <Shield className="w-12 h-12 text-primary mr-3" />
            <div>
              <h1 className="text-2xl font-bold text-foreground">MIL-Malware Analyzer</h1>
              <p className="text-muted-foreground text-sm">Autenticación Segura</p>
            </div>
          </div>

          {/* Mensaje de Error */}
          {error && (
            <div className="mb-4 p-3 rounded bg-destructive/10 border border-destructive/20 text-destructive text-xs text-center font-medium">
              {error}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-6">
            {/* Usuario */}
            <div>
              <label htmlFor="username" className="block text-sm mb-2 text-foreground font-medium">
                Nombre de usuario
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-input border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary text-foreground transition-all"
                  placeholder="Ingrese su usuario"
                  required
                  disabled={isLoading}
                />
              </div>
            </div>

            {/* Contraseña */}
            <div>
              <label htmlFor="password" className="block text-sm mb-2 text-foreground font-medium">
                Contraseña
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-input border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary text-foreground transition-all"
                  placeholder="Ingrese su contraseña"
                  required
                  disabled={isLoading}
                />
              </div>
            </div>

            {/* Botón de Ingreso */}
            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-primary text-primary-foreground py-3 rounded-md hover:opacity-90 transition-all font-semibold disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Verificando...
                </>
              ) : (
                'Iniciar Sesión'
              )}
            </button>
          </form>

          <div className="mt-6 text-center text-xs text-muted-foreground">
            <p className="flex items-center justify-center gap-1">
              <Lock className="w-3 h-3" />
              Conexión Encriptada
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}