import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area, BarChart, Bar, Legend } from 'recharts';
import { Activity, Cpu, Database, Shield, Users, CheckCircle, XCircle, ArrowLeft, Loader2, LogOut } from 'lucide-react';
import { apiClient } from '../services/api.client';
import { authService } from '../services/auth.service';

function UserPodium({ data }: { data: any[] }) {
  const sorted = [...data].sort((a, b) => b.risk_score - a.risk_score);
  const [first, second, third] = sorted;

  return (
    <div className="flex items-end justify-center gap-4 h-56 mb-8">
      {/* 2º PUESTO (PLATA) */}
      {second && (
        <div className="flex flex-col items-center w-24">
          <span className="text-xs mb-1 text-gray-300 font-medium">{second.usuario__username}</span>
          <div className="w-full h-24 bg-gray-400/20 border-t-4 border-gray-400 flex items-center justify-center font-bold text-gray-300 shadow-lg">
            2º
          </div>
        </div>
      )}

      {/* 1º PUESTO (ORO) */}
      {first && (
        <div className="flex flex-col items-center w-24">
          <span className="text-xs mb-1 text-yellow-400 font-bold">{first.usuario__username}</span>
          <div className="w-full h-36 bg-yellow-500/20 border-t-4 border-yellow-500 flex items-center justify-center font-bold text-yellow-400 shadow-xl">
            1º
          </div>
        </div>
      )}

      {/* 3º PUESTO (BRONCE) */}
      {third && (
        <div className="flex flex-col items-center w-24">
          <span className="text-xs mb-1 text-amber-700 font-medium">{third.usuario__username}</span>
          <div className="w-full h-16 bg-amber-700/20 border-t-4 border-amber-700 flex items-center justify-center font-bold text-amber-700 shadow-lg">
            3º
          </div>
        </div>
      )}
    </div>
  );
}



export function AdminDashboard() {
  const navigate = useNavigate();
  const [data, setData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);

  const handleUpdatePseudoLabel = async (id: number, nuevoValor: boolean) => {
    try {
      // 1. Petición al backend
      const response = await apiClient(`/admin/${id}/toggle-pseudo-label/`, {
        method: 'PATCH',
        body: JSON.stringify({ pseudo_label: nuevoValor }),
      });
  
      if (response.ok) {
        // 2. Actualización dinámica en LOCAL
        // Asumiendo que tu estado se llama 'data' y tiene una propiedad 'pseudo_labels'
        setData((prevData: any) => {
          if (!prevData) return prevData;
  
          return {
            ...prevData,
            pseudo_labels: prevData.pseudo_labels.map((item: any) => {
              if (item.id === id) {
                // Devolvemos el item con el nuevo valor booleano
                return { ...item, pseudo_label: nuevoValor };
              }
              return item;
            }),
          };
        });
      }
    } catch (error) {
      console.error("Error al actualizar el estado local:", error);
    }
  };

  useEffect(() => {
    const fetchData = async () => {
      setIsLoading(true);
      try {
        const res = await apiClient('/admin/dashboard-stats/');
        const result = await res.json();
        setData(result);
      } catch (err) {
        if (err === 'Forbidden') {
          navigate('/dashboard', { state: { error: "No tienes permisos de administrador" } });
        } else {
          console.error("Error al cargar dashboard:", err);
          
        }
      } finally {
        setIsLoading(false);
      }
    };
    fetchData();
  }, [navigate]);

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
        <div className="flex items-center justify-between w-full">
          
          {/* Contenedor izquierdo: Título e Icono */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-destructive/20 rounded-lg flex items-center justify-center">
              <Shield className="w-6 h-6 text-destructive" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground">Panel de Administración</h1>
              <p className="text-xs text-muted-foreground">Estado del Sistema y Gestión</p>
            </div>
          </div>

          <button
            onClick={() => authService.logout()}
            className="bg-secondary text-secondary-foreground px-4 py-2 rounded-md hover:bg-secondary/50 transition-all flex items-center gap-2 border border-white/10"
          >
            <LogOut className="w-4 h-4" />
            Cerrar Sesión
          </button>
          
        </div>
      </header>

      <div className="p-8 space-y-8">
        {/* KPIs Dinámicos */}
        <div className="grid grid-cols-4 gap-6">
          <KPICard title="Carga de GPU" value={`${data.kpis.gpu_load}%`} icon={Cpu} color="text-accent" />
          <KPICard title="Carga de CPU" value={`${data.kpis.cpu_load.toFixed(1)}%`} icon={Activity} color="text-primary" />
          <KPICardUsers 
            title="Usuarios Activos" 
            value={data.kpis.active_users} 
            icon={Users} 
            color="text-primary" 
            activeUsersList={data.active_users_list} 
          />
          <KPICard title="Tamaño del Dataset" value={data.kpis.dataset_size} icon={Database} color="text-accent" onClick={() => navigate('/dataset-explorer')}/>
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
                <Tooltip contentStyle={{ backgroundColor: '#1E1E1E', color: 'white' }} />
                <Area name="GPU" dataKey="gpu" stroke="#FFA500" fill="transparent" fillOpacity={0.3} />
                <Area name="CPU" dataKey="cpu" stroke="#00FF41" fill="transparent" fillOpacity={0.3} />
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
                <Tooltip contentStyle={{ backgroundColor: '#1E1E1E', color: 'white' }} />
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
                  <td className="py-3 px-4">
                    <div className="flex items-center justify-center min-w-[100px]">
                      {/* Usamos el valor booleano que actualizamos en el paso anterior */}
                      {item.pseudo_label ? (
                        /* SI ES TRUE: Mostramos botón para poner a FALSE (X) */
                        <button
                          onClick={() => handleUpdatePseudoLabel(item.id, false)}
                          className="group flex items-center gap-2 text-destructive hover:bg-destructive/10 px-2 py-1 rounded-md transition-all"
                        >
                          <XCircle className="w-5 h-5" />
                          <span className="text-[10px] font-bold uppercase hidden group-hover:block">
                            Desactivar
                          </span>
                        </button>
                      ) : (
                        /* SI ES FALSE: Mostramos botón para poner a TRUE (Tick) */
                        <button
                          onClick={() => handleUpdatePseudoLabel(item.id, true)}
                          className="group flex items-center gap-2 text-emerald-500 hover:bg-emerald-500/10 px-2 py-1 rounded-md transition-all"
                        >
                          <CheckCircle className="w-5 h-5" />
                          <span className="text-[10px] font-bold uppercase hidden group-hover:block">
                            Activar
                          </span>
                        </button>
                      )}
                    </div>
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
        {/* Sección de Reputación */}
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold text-foreground mb-6 flex items-center gap-2">
            <Shield className="w-5 h-5 text-destructive" /> 
            Top 3 Usuarios con Mayor Riesgo
          </h2>
          {data.user_reputation && data.user_reputation.length > 0 ? (
            <UserPodium data={data.user_reputation} />
          ) : (
            <p className="text-muted-foreground text-center py-10">No hay datos de riesgo suficientes.</p>
          )}
        </div>
      </div>
    </div>
  );
}

// Componente auxiliar para limpiar el código
function KPICard({ title, value, icon: Icon, color, onClick }: any) {
  return (
    <div 
      onClick={onClick}
      className={`bg-card border border-border rounded-lg p-6 shadow-sm transition-all ${
        onClick ? 'cursor-pointer hover:border-primary/50 hover:bg-secondary/20' : 'cursor-default'
      }`}
    >
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm text-muted-foreground font-medium">{title}</h3>
        <Icon className={`w-5 h-5 ${color}`} />
      </div>
      <p className="text-3xl font-bold text-foreground">{value}</p>
    </div>
  );
}

function KPICardUsers({ title, value, icon: Icon, color, activeUsersList }: any) {
  return (
    /* Importante: la clase 'group' es la que permite que el hijo detecte el hover del padre */
    <div className="bg-card border border-border rounded-lg p-6 shadow-sm relative group">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm text-muted-foreground font-medium">{title}</h3>
        <Icon className={`w-5 h-5 ${color}`} />
      </div>
      <p className="text-3xl font-bold text-foreground">{value}</p>

      {/* TOOLTIP: Solo se muestra si hay usuarios y si el ratón está sobre la tarjeta (group-hover) */}
      {activeUsersList && activeUsersList.length > 0 && (
        <div className="absolute z-[100] left-0 top-[110%] w-56 bg-[#1E1E1E] border border-border rounded-lg shadow-2xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 p-4">
          <p className="text-[10px] uppercase tracking-wider font-bold text-primary mb-3 border-b border-white/10 pb-2">
            Usuarios en línea
          </p>
          <ul className="space-y-2 max-h-40 overflow-y-auto custom-scrollbar">
            {activeUsersList.map((user: string, index: number) => (
              <li key={index} className="text-sm text-gray-200 flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                <span className="font-mono">{user}</span>
              </li>
            ))}
          </ul>
          {/* Triangulito del tooltip (opcional) */}
          <div className="absolute -top-1.5 left-6 w-3 h-3 bg-[#1E1E1E] border-l border-t border-border rotate-45"></div>
        </div>
      )}
    </div>
  );

}