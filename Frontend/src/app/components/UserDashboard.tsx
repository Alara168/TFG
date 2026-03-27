import { useEffect, useState, useMemo } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { FileText, Upload, Eye, Loader2, LogOut } from 'lucide-react';
import { toast } from 'react-hot-toast';
import { apiClient } from '../services/api.client';
import { authService } from '../services/auth.service';

interface AnalysisRecord {
  id_analisis: number;
  nombre_fichero_personalizado: string;
  hash_sha256: string;
  resultado_clase: string;
  confianza_global: number;
  tamano_bytes: number;
  fecha_subida: string;
}

const MALWARE_COLORS = {
  benigno: '#22c55e',
  ransomware: '#ef4444',
  financiero: '#f97316',
  sistema: '#eab308',
  intrusion: '#a855f7',
};

export function UserDashboard() {
  const navigate = useNavigate();
  const location = useLocation();
  const [history, setHistory] = useState<AnalysisRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    if (location.state?.error) {
      toast.error(location.state.error);
      navigate(location.pathname, { replace: true, state: {} });
    }
  }, [location.state, location.pathname, navigate]);

  useEffect(() => {
    const fetchHistorial = async () => {
      try {
        const response = await apiClient('/historial/');
        if (response.ok) {
          const data = await response.json();
          setHistory(data);
        }
      } catch (error) {
        console.error('Error al obtener el historial:', error);
      } finally {
        setIsLoading(false);
      }
    };
    fetchHistorial();
  }, []);

  // --- PROCESAMIENTO DINÁMICO CORREGIDO ---
  const dynamicTrendData = useMemo(() => {
    const monthNames = ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun', 'Jul', 'Ago', 'Sep', 'Oct', 'Nov', 'Dic'];
    
    // Si no hay datos, devolvemos un array con el mes actual vacío para que el gráfico no rompa
    if (history.length === 0) {
      return [{ month: monthNames[new Date().getMonth()], Ransom: 0, Financiero: 0, Sistema: 0, Intrusion: 0, Benigno: 0 }];
    }

    const agrupado = history.reduce((acc: any, item) => {
      const fecha = new Date(item.fecha_subida);
      const mesNombre = monthNames[fecha.getMonth()];
      const anio = fecha.getFullYear();
      const key = `${anio}-${fecha.getMonth().toString().padStart(2, '0')}`;

      if (!acc[key]) {
        acc[key] = { 
          month: mesNombre,
          Ransom: 0, 
          Financiero: 0, 
          Sistema: 0, 
          Intrusion: 0, 
          Benigno: 0,
          sortKey: key 
        };
      }

      const res = item.resultado_clase.toLowerCase();
      if (res.includes('benigno')) acc[key].Benigno++;
      else if (res.includes('ransom')) acc[key].Ransom++;
      else if (res.includes('financiero')) acc[key].Financiero++;
      else if (res.includes('sistema') || res.includes('herramientas')) acc[key].Sistema++;
      else if (res.includes('intrusion')) acc[key].Intrusion++;

      return acc;
    }, {});

    // Ordenar por año-mes y devolver
    return Object.values(agrupado).sort((a: any, b: any) => a.sortKey.localeCompare(b.sortKey));
  }, [history]);

  const getStatusColor = (status: string) => {
    const s = status.toLowerCase();
    if (s.includes('benigno')) return 'text-[#22c55e]';
    if (s.includes('ransom')) return 'text-[#ef4444]';
    if (s.includes('financiero')) return 'text-[#f97316]';
    if (s.includes('herramientas') || s.includes('sistema')) return 'text-[#eab308]';
    if (s.includes('intrusion')) return 'text-[#a855f7]';
    return 'text-destructive';
  };

  const getScoreColor = (score: number, resultado: string) => {
    if (resultado.toLowerCase().includes('benigno')) return 'text-[#22c55e]';
    const s = score * 100;
    if (s >= 80) return 'text-destructive';
    if (s >= 50) return 'text-accent';
    return 'text-primary';
  };

  const totalFiles = history.length;
  const highRiskCount = history.filter(item => !item.resultado_clase.toLowerCase().includes('benigno')).length;

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="bg-card border-b border-border px-8 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-primary/20 rounded-lg flex items-center justify-center">
              <FileText className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold">MIL-Malware Analyzer</h1>
              <p className="text-xs text-muted-foreground">Panel de Análisis</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => navigate('/upload')} className="bg-primary text-primary-foreground px-6 py-2 rounded-md hover:bg-primary/50 transition-all flex items-center gap-2">
              <Upload className="w-4 h-4" /> Nuevo Análisis
            </button>
            <button onClick={() => authService.logout()} className="bg-secondary text-secondary-foreground px-4 py-2 rounded-md hover:bg-secondary/50 transition-all flex items-center gap-2 border border-border">
              <LogOut className="w-4 h-4" /> Cerrar Sesión
            </button>
          </div>
        </div>
      </header>

      <div className="p-8 space-y-8">
        <div className="grid grid-cols-3 gap-6">
          <div className="bg-card border border-border rounded-lg p-6 shadow-sm">
            <h3 className="text-sm text-muted-foreground mb-2">Total Analizados</h3>
            <p className="text-3xl font-bold">{totalFiles}</p>
          </div>
          <div className="bg-card border border-border rounded-lg p-6 shadow-sm">
            <h3 className="text-sm text-muted-foreground mb-2">Amenazas Detectadas</h3>
            <p className="text-3xl font-bold text-destructive">{highRiskCount}</p>
          </div>
          <div className="bg-card border border-border rounded-lg p-6 shadow-sm">
            <h3 className="text-sm text-muted-foreground mb-2">Tasa de Detección</h3>
            <p className="text-3xl font-bold">{totalFiles > 0 ? ((highRiskCount / totalFiles) * 100).toFixed(1) : 0}%</p>
          </div>
        </div>

        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Tendencias de Amenazas</h2>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={dynamicTrendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#333" />
              <XAxis dataKey="month" stroke="#888" fontSize={12} />
              <YAxis stroke="#888" fontSize={12} />
              <Tooltip contentStyle={{ backgroundColor: '#1E1E1E', border: '1px solid #333', borderRadius: '8px' }} />
              <Legend />
              <Line name="Otros/Ransom" type="monotone" dataKey="Ransom" stroke={MALWARE_COLORS.ransomware} strokeWidth={2} />
              <Line name="Financiero" type="monotone" dataKey="Financiero" stroke={MALWARE_COLORS.financiero} strokeWidth={2} />
              <Line name="Herramientas/Sistema" type="monotone" dataKey="Sistema" stroke={MALWARE_COLORS.sistema} strokeWidth={2} />
              <Line name="Intrusión" type="monotone" dataKey="Intrusion" stroke={MALWARE_COLORS.intrusion} strokeWidth={2} />
              <Line name="Benigno" type="monotone" dataKey="Benigno" stroke={MALWARE_COLORS.benigno} strokeWidth={2} strokeDasharray="5 5" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Historial de Análisis</h2>
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-12 gap-3">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left py-3 px-4 text-xs text-muted-foreground uppercase font-semibold">Archivo</th>
                    <th className="text-left py-3 px-4 text-xs text-muted-foreground uppercase font-semibold">Resultado</th>
                    <th className="text-left py-3 px-4 text-xs text-muted-foreground uppercase font-semibold">Confianza</th>
                    <th className="text-left py-3 px-4 text-xs text-muted-foreground uppercase font-semibold">Acción</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((item) => (
                    <tr key={item.id_analisis} className="border-b border-border hover:bg-secondary/30 cursor-pointer" onClick={() => navigate(`/analisis/${item.id_analisis}`)}>
                      <td className="py-4 px-4 font-mono text-sm">{item.nombre_fichero_personalizado}</td>
                      <td className="py-4 px-4">
                        <span className={`text-sm font-bold ${getStatusColor(item.resultado_clase)}`}>{item.resultado_clase}</span>
                      </td>
                      <td className="py-4 px-4">
                        <span className={`text-sm font-bold ${getScoreColor(item.confianza_global, item.resultado_clase)}`}>{(item.confianza_global * 100).toFixed(2)}%</span>
                      </td>
                      <td className="py-4 px-4">
                        <button className="text-primary hover:text-primary/80 flex items-center gap-1 text-sm font-semibold" onClick={(e) => { e.stopPropagation(); navigate(`/analisis/${item.id_analisis}`); }}>
                          <Eye className="w-4 h-4" /> Ver
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}