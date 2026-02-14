import { useNavigate } from 'react-router-dom';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { Activity, Cpu, Database, Shield, Users, CheckCircle, XCircle, ArrowLeft } from 'lucide-react';

const performanceData = [
  { time: '00:00', precision: 0.94, recall: 0.91 },
  { time: '04:00', precision: 0.96, recall: 0.93 },
  { time: '08:00', precision: 0.95, recall: 0.94 },
  { time: '12:00', precision: 0.97, recall: 0.95 },
  { time: '16:00', precision: 0.96, recall: 0.94 },
  { time: '20:00', precision: 0.98, recall: 0.96 },
];

const resourceData = [
  { time: '00:00', gpu: 45, cpu: 32 },
  { time: '04:00', gpu: 52, cpu: 38 },
  { time: '08:00', gpu: 78, cpu: 65 },
  { time: '12:00', gpu: 85, cpu: 72 },
  { time: '16:00', gpu: 68, cpu: 54 },
  { time: '20:00', gpu: 42, cpu: 30 },
];

const pseudoLabels = [
  { id: 1, filename: 'muestra_001.exe', confidence: 0.96, prediction: 'Malicioso', status: 'pendiente' },
  { id: 2, filename: 'muestra_002.dll', confidence: 0.89, prediction: 'Benigno', status: 'pendiente' },
  { id: 3, filename: 'muestra_003.bin', confidence: 0.92, prediction: 'Malicioso', status: 'pendiente' },
  { id: 4, filename: 'muestra_004.elf', confidence: 0.88, prediction: 'Benigno', status: 'pendiente' },
];

const userLogs = [
  { id: 1, user: 'analista_01', action: 'Análisis de Archivo', timestamp: '2026-01-03 14:23:15', ip: '192.168.1.10' },
  { id: 2, user: 'analista_02', action: 'Exportar Reporte', timestamp: '2026-01-03 14:15:42', ip: '192.168.1.11' },
  { id: 3, user: 'admin_root', action: 'Actualización de Modelo', timestamp: '2026-01-03 13:58:30', ip: '192.168.1.5' },
  { id: 4, user: 'analista_01', action: 'Subida de Archivo', timestamp: '2026-01-03 13:45:12', ip: '192.168.1.10' },
];

export function AdminDashboard() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="bg-card border-b border-border px-8 py-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/dashboard')}
            className="text-muted-foreground hover:text-foreground transition-colors"
          >
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
        {/* KPIs de Métricas del Sistema */}
        <div className="grid grid-cols-4 gap-6">
          <div className="bg-card border border-border rounded-lg p-6 shadow-sm">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm text-muted-foreground font-medium">Carga de GPU</h3>
              <Cpu className="w-5 h-5 text-accent" />
            </div>
            <p className="text-3xl font-bold text-foreground">68%</p>
            <p className="text-xs text-muted-foreground mt-1">Inferencia MIL activa</p>
          </div>

          <div className="bg-card border border-border rounded-lg p-6 shadow-sm">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm text-muted-foreground font-medium">Carga de CPU</h3>
              <Activity className="w-5 h-5 text-primary" />
            </div>
            <p className="text-3xl font-bold text-foreground">54%</p>
            <p className="text-xs text-muted-foreground mt-1">Uso promedio del sistema</p>
          </div>

          <div className="bg-card border border-border rounded-lg p-6 shadow-sm">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm text-muted-foreground font-medium">Usuarios Activos</h3>
              <Users className="w-5 h-5 text-primary" />
            </div>
            <p className="text-3xl font-bold text-foreground">24</p>
            <p className="text-xs text-muted-foreground mt-1">Sesiones en línea</p>
          </div>

          <div className="bg-card border border-border rounded-lg p-6 shadow-sm">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm text-muted-foreground font-medium">Tamaño del Dataset</h3>
              <Database className="w-5 h-5 text-accent" />
            </div>
            <p className="text-3xl font-bold text-foreground">45K</p>
            <p className="text-xs text-muted-foreground mt-1">Muestras de entrenamiento</p>
          </div>
        </div>

        {/* Fila de Gráficos */}
        <div className="grid grid-cols-2 gap-6">
          {/* Gráfico de Recursos */}
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Utilización de Recursos (24h)</h2>
            <ResponsiveContainer width="100%" height={250}>
              <AreaChart data={resourceData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis dataKey="time" stroke="#888" />
                <YAxis stroke="#888" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1E1E1E', border: '1px solid #333', borderRadius: '8px' }}
                  labelStyle={{ color: '#E0E0E0' }}
                />
                <Area name="GPU" type="monotone" dataKey="gpu" stroke="#FFA500" fill="#FFA500" fillOpacity={0.3} />
                <Area name="CPU" type="monotone" dataKey="cpu" stroke="#00FF41" fill="#00FF41" fillOpacity={0.3} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Gráfico de Rendimiento del Modelo */}
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Métricas del Modelo (Precisión / Recall)</h2>
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={performanceData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                <XAxis dataKey="time" stroke="#888" />
                <YAxis domain={[0.85, 1]} stroke="#888" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1E1E1E', border: '1px solid #333', borderRadius: '8px' }}
                  labelStyle={{ color: '#E0E0E0' }}
                />
                <Line name="Precisión" type="monotone" dataKey="precision" stroke="#00FF41" strokeWidth={2} dot={{ fill: '#00FF41' }} />
                <Line name="Recall" type="monotone" dataKey="recall" stroke="#00D4FF" strokeWidth={2} dot={{ fill: '#00D4FF' }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Gestión del Dataset */}
        <div className="bg-card border border-border rounded-lg p-6 shadow-sm">
          <h2 className="text-lg font-semibold text-foreground mb-4">Gestión del Dataset - Pseudo-etiquetado</h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Nombre del Archivo</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Confianza</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Predicción</th>
                  <th className="text-left py-3 px-4 text-sm text-muted-foreground">Acciones</th>
                </tr>
              </thead>
              <tbody>
                {pseudoLabels.map((item) => (
                  <tr key={item.id} className="border-b border-border hover:bg-secondary/50 transition-colors">
                    <td className="py-3 px-4">
                      <span className="text-foreground font-mono text-sm">{item.filename}</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-foreground font-mono">{(item.confidence * 100).toFixed(1)}%</span>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`text-sm font-semibold ${item.prediction === 'Malicioso' ? 'text-destructive' : 'text-primary'}`}>
                        {item.prediction}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <button className="text-primary hover:text-primary/80 flex items-center gap-1 text-sm font-medium transition-colors">
                          <CheckCircle className="w-4 h-4" />
                          Aprobar
                        </button>
                        <button className="text-destructive hover:text-destructive/80 flex items-center gap-1 text-sm font-medium transition-colors">
                          <XCircle className="w-4 h-4" />
                          Rechazar
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Logs de Acceso */}
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
                {userLogs.map((log) => (
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