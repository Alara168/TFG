import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, User, Loader2, Mail, ArrowLeft, Eye, EyeOff } from 'lucide-react';

export function Registro() {
  const [formData, setFormData] = useState({
    username: '', email: '', password: '', first_name: '', last_name: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const handleRegistro = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    try {
      const response = await fetch('http://127.0.0.1:8000/api/registro/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      if (!response.ok) throw new Error('Error al registrar usuario');
      navigate('/login');
    } catch (err: any) {
      setError(err.message || 'Error de conexión');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background relative overflow-hidden">
      {/* Fondo binario de pantalla completa */}
      <div className="fixed inset-0 opacity-10 pointer-events-none z-0 overflow-hidden select-none">
        <div className="font-mono text-[#00FF41] text-xs leading-none h-full w-full break-all">
          {Array.from({ length: 100 }).map((_, i) => (
            <div key={i} className="whitespace-nowrap overflow-hidden">
              {Array.from({ length: 300 }).map(() => (Math.random() > 0.5 ? '1' : '0')).join('')}
            </div>
          ))}
        </div>
      </div>

      <div className="w-full max-w-md px-6 relative z-10">
        <div className="bg-card border border-border rounded-lg p-8 shadow-2xl">
          <button onClick={() => navigate('/login')} className="flex items-center text-sm text-muted-foreground hover:text-foreground mb-6 transition-colors">
            <ArrowLeft className="w-4 h-4 mr-2" /> Volver al Login
          </button>

          <div className="flex items-center mb-8">
            <Shield className="w-10 h-10 text-primary mr-3" />
            <div>
              <h1 className="text-2xl font-bold text-foreground">Crear Cuenta</h1>
              <p className="text-muted-foreground text-sm">Registro de nuevo analista</p>
            </div>
          </div>

          {error && <div className="mb-4 p-3 rounded bg-destructive/10 border border-destructive/20 text-destructive text-xs text-center font-medium">{error}</div>}

          <form onSubmit={handleRegistro} className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <input type="text" placeholder="Nombre" className="w-full px-4 py-2 bg-input border border-border rounded-md text-foreground focus:ring-2 focus:ring-primary outline-none" onChange={(e) => setFormData({...formData, first_name: e.target.value})} required />
              <input type="text" placeholder="Apellidos" className="w-full px-4 py-2 bg-input border border-border rounded-md text-foreground focus:ring-2 focus:ring-primary outline-none" onChange={(e) => setFormData({...formData, last_name: e.target.value})} required />
            </div>
            
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <input type="text" placeholder="Usuario" className="w-full pl-10 pr-4 py-2 bg-input border border-border rounded-md text-foreground focus:ring-2 focus:ring-primary outline-none" onChange={(e) => setFormData({...formData, username: e.target.value})} required />
            </div>
            
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <input type="email" placeholder="Correo electrónico" className="w-full pl-10 pr-4 py-2 bg-input border border-border rounded-md text-foreground focus:ring-2 focus:ring-primary outline-none" onChange={(e) => setFormData({...formData, email: e.target.value})} required />
            </div>
            
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
              <input type={showPassword ? "text" : "password"} placeholder="Contraseña" className="w-full pl-10 pr-10 py-2 bg-input border border-border rounded-md text-foreground focus:ring-2 focus:ring-primary outline-none" onChange={(e) => setFormData({...formData, password: e.target.value})} required />
              <button type="button" onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>

            <button type="submit" disabled={isLoading} className="w-full bg-primary text-primary-foreground py-3 rounded-md font-semibold hover:opacity-90 transition-all flex items-center justify-center gap-2">
              {isLoading ? <><Loader2 className="w-4 h-4 animate-spin" /> Registrando...</> : 'Registrarse'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}