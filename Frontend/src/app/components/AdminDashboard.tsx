import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area, BarChart, Bar, Legend } from 'recharts';
import { Activity, Cpu, Database, Shield, Users, CheckCircle, XCircle, ArrowLeft, Loader2 } from 'lucide-react';
import { apiClient } from '../services/api.client';

export function AdminDashboard() {
  const navigate = useNavigate();
  const [data, setData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      setIsLoading(true);
      try {
        const res = await apiClient('/admin/dashboard-stats/');
        if (res.ok) {
          const result = await res.json();
          setData(result);
        }
      } catch (err) {
        console.error("Error al cargar dashboard:", err);
      } finally {
        setIsLoading(false);
      }
    };
    fetchData();
  }, []);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="min-h-screen bg-background">
      <header className="bg-card border-b border-border px-8 py-4">
        <div className="flex items-center gap-3">
          <button onClick={() => navigate('/dashboard')} className="text-muted-foreground hover:text-foreground transition-colors">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-destructive/20 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-destructive" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground">Panel de Administración</h1>
              <p className="text-xs text-muted-foreground">Estado del Sistema y Gestión</p>
            </div>
          </div>
        </div>
      </header>

      <div className="p-8 space-y-8">
        {/* KPIs Dinámicos */}
        <div className="grid grid-cols-4 gap-6">
          <KPICard title="Carga de GPU" value={`${data.kpis.gpu_load}%`} icon={Cpu} color="text-accent" />
          <KPICard title="Carga de CPU" value={`${data.kpis.cpu_load.toFixed(1)}%`} icon={Activity} color="text-primary" />
          <KPICard title="Usuarios Activos" value={data.kpis.active_users} icon={Users} color="text-primary" />
          <KPICard title="Tamaño del Dataset" value={data.kpis.dataset_size} icon={Database} color="text-accent" />
        </div>

        {/* Gráficos */}
        <div className="grid grid-cols-2 gap-6">
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Utilización de Recursos (24h)</h2>
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={data.charts.resource_usage}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis dataKey="time" stroke="#888" />
                <YAxis stroke="#888" />
                <Tooltip contentStyle={{ backgroundColor: '#1E1E1E' }} />
                <Area name="GPU" dataKey="gpu" stroke="#FFA500" fill="#FFA500" fillOpacity={0.3} />
                <Area name="CPU" dataKey="cpu" stroke="#00FF41" fill="#00FF41" fillOpacity={0.3} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          {/* Métricas de Performance del Modelo */}
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Rendimiento por Categoría</h2>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={data.charts.model_performance}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#333" />
                <XAxis dataKey="name" stroke="#888" fontSize={12} />
                <YAxis domain={[0, 1]} stroke="#888" fontSize={12} />
                <Tooltip contentStyle={{ backgroundColor: '#1E1E1E' }} />
                <Legend />
                <Bar dataKey="precision" name="Precisión" fill="#8884d8" />
                <Bar dataKey="recall" name="Recall" fill="#82ca9d" />
                <Bar dataKey="f1" name="F1" fill="#ffc658" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Tabla de Pseudo-etiquetado */}
        <div className="bg-card border border-border rounded-lg p-6 shadow-sm">
          <h2 className="text-lg font-semibold text-foreground mb-4">Gestión del Dataset</h2>
          <table className="w-full">
            <tbody>
              {data.pseudo_labels.map((item: any) => (
                <tr key={item.id} className="border-b border-border">
                  <td className="py-3 px-4 font-mono text-sm text-foreground">{item.filename}</td>
                  <td className="py-3 px-4 text-foreground">{(item.confidence * 100).toFixed(1)}%</td>
                  <td className="py-3 px-4 text-primary font-semibold">{item.prediction}</td>
                  <td className="py-3 px-4 flex gap-2">
                    <CheckCircle className="w-4 h-4 text-primary cursor-pointer" />
                    <XCircle className="w-4 h-4 text-destructive cursor-pointer" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {/* Registros de Acceso */}
        <div className="bg-card border border-border rounded-lg p-6 shadow-sm">
          <h2 className="text-lg font-semibold text-foreground mb-4">Registros de Acceso de Usuarios</h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Usuario</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Acción</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Marca de Tiempo</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Dirección IP</th>
                </tr>
              </thead>
              <tbody>
                {data.user_logs.map((log: any) => (
                  <tr key={log.id} className="border-b border-border hover:bg-secondary/50 transition-colors">
                    <td className="py-3 px-4">
                      <span className="text-foreground font-mono text-sm">{log.user}</span>
                    </td>
                    <td className="py-3 px-4 text-sm text-foreground">{log.action}</td>
                    <td className="py-3 px-4 text-sm text-muted-foreground font-mono">{log.timestamp}</td>
                    <td className="py-3 px-4 text-sm text-muted-foreground font-mono">{log.ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

// Componente auxiliar para limpiar el código
function KPICard({ title, value, icon: Icon, color }: any) {
  return (
    <div className="bg-card border border-border rounded-lg p-6 shadow-sm">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm text-muted-foreground font-medium">{title}</h3>
        <Icon className={`w-5 h-5 ${color}`} />
      </div>
      <p className="text-3xl font-bold text-foreground">{value}</p>
    </div>
  );
}