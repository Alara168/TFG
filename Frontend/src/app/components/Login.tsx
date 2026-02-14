import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, User } from 'lucide-react';

export function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const navigate = useNavigate();

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    // Navigate to dashboard after "login"
    navigate('/dashboard');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background relative overflow-hidden">
      {/* Binary code rain background effect */}
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
          {/* Header */}
          <div className="flex items-center justify-center mb-8">
            <Shield className="w-12 h-12 text-primary mr-3" />
            <div>
              <h1 className="text-2xl font-bold text-foreground">MIL-Malware Analyzer</h1>
              <p className="text-muted-foreground text-sm">Secure Authentication</p>
            </div>
          </div>

          <form onSubmit={handleLogin} className="space-y-6">
            {/* Username */}
            <div>
              <label htmlFor="username" className="block text-sm mb-2 text-foreground">
                Username
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-input border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary text-foreground"
                  placeholder="Enter username"
                  required
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label htmlFor="password" className="block text-sm mb-2 text-foreground">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-input border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary text-foreground"
                  placeholder="Enter password"
                  required
                />
              </div>
            </div>

            

            {/* Login Button */}
            <button
              type="submit"
              className="w-full bg-primary text-primary-foreground py-3 rounded-md hover:opacity-90 transition-opacity font-semibold"
            >
              Login
            </button>
          </form>

          <div className="mt-6 text-center text-xs text-muted-foreground">
            <p>Encrypted Connection</p>
          </div>
        </div>
      </div>
    </div>
  );
}
