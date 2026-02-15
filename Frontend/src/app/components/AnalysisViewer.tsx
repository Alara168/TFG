import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, AlertTriangle, Shield, Filter, Code, Loader2, Database, Activity, Cpu } from 'lucide-react';
import { apiClient } from '../services/api.client';

// Interfaces
interface FunctionNode {
  id: string;
  name: string;
  attention: number;
  x: number;
  y: number;
  calls: string[];
}

// DATOS ESTÁTICOS (Los que se verán por ahora)
const staticFunctionNodes: FunctionNode[] = [
  { id: '1', name: 'main', attention: 0.95, x: 400, y: 50, calls: ['2', '3'] },
  { id: '2', name: 'encrypt_files', attention: 0.98, x: 250, y: 150, calls: ['4', '5'] },
  { id: '3', name: 'connect_c2', attention: 0.92, x: 550, y: 150, calls: ['6'] },
  { id: '4', name: 'file_walker', attention: 0.85, x: 150, y: 250, calls: [] },
  { id: '5', name: 'aes_encrypt', attention: 0.90, x: 350, y: 250, calls: [] },
  { id: '6', name: 'send_data', attention: 0.88, x: 550, y: 250, calls: [] },
  { id: '7', name: 'keylogger', attention: 0.65, x: 700, y: 250, calls: [] },
];

export function AnalysisViewer() {
  const navigate = useNavigate();
  const { id } = useParams();
  
  // ESTADOS PARA GUARDAR DATOS DE LA API (Sin usar todavía en el render)
  const [apiAnalysis, setApiAnalysis] = useState<any>(null);
  const [apiGraph, setApiGraph] = useState<any>(null);
  
  // ESTADOS DE CONTROL
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [attentionFilter, setAttentionFilter] = useState(0);
  const [selectedFunction, setSelectedFunction] = useState<FunctionNode | null>(null);

  // PETICIONES A LA API
  useEffect(() => {
    const fetchData = async () => {
      if (!id) return;
      setIsLoading(true);
      try {
        // Realizamos las dos llamadas
        const [resDetail, resGraph] = await Promise.all([
          apiClient(`/analisis/${id}/`),
          apiClient(`/analisis/${id}/grafo/`)
        ]);

        if (resDetail.ok) {
          const detailData = await resDetail.json();
          setApiAnalysis(detailData);
          console.log("API Detail Data:", detailData);
        }

        if (resGraph.ok) {
          const graphData = await resGraph.json();
          setApiGraph(graphData);
          console.log("API Graph Data:", graphData);
        }

      } catch (err: any) {
        if (err !== 'Unauthorized') {
          console.error("Fetch error:", err);
          // No bloqueamos la UI con setError para poder ver los datos estáticos
        }
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [id]);

  // FILTRO (Usando datos estáticos por ahora)
  const filteredNodes = staticFunctionNodes.filter(node => node.attention >= attentionFilter);

  const getNodeColor = (attention: number) => {
    if (attention >= 0.8) return '#FF3131';
    if (attention >= 0.5) return '#FFA500';
    return '#00FF41';
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex flex-col items-center justify-center">
        <Loader2 className="w-12 h-12 animate-spin text-primary mb-4" />
        <p className="text-muted-foreground font-mono">Consultando base de datos...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background flex flex-col text-foreground overflow-hidden">
      {/* CABECERA */}
      <header className="bg-card border-b border-border px-8 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button onClick={() => navigate('/dashboard')} className="text-muted-foreground hover:text-foreground">
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div>
              <h1 className="text-xl font-bold">Análisis de Binario</h1>
              {/* Mostramos el nombre de la API si ya cargó, sino el estático */}
              <p className="text-xs text-muted-foreground font-mono">
                {apiAnalysis?.nombre_fichero || "malware_sample_1.exe"}
              </p>
            </div>
          </div>
          <button onClick={() => navigate('/dashboard')} className="text-sm text-primary font-medium">
            Volver al Historial
          </button>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        {/* BARRA LATERAL IZQUIERDA (Estática por ahora) */}
        <div className="w-80 bg-card border-r border-border p-6 space-y-6 overflow-y-auto">
          <div>
            <h2 className="text-lg font-semibold mb-4">Clasificación</h2>
            <div className="bg-destructive/10 border border-destructive rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-6 h-6 text-destructive" />
                <span className="font-bold text-2xl text-destructive">
                   {apiAnalysis ? (apiAnalysis.confianza_global * 100).toFixed(0) : '98'}%
                </span>
              </div>
              <p className="text-destructive font-semibold">
                {apiAnalysis?.resultado_clase || "Malicioso"}
              </p>
              <p className="text-sm text-destructive/80 mt-1">Familia: Ransomware</p>
            </div>
          </div>

          {/* Metadata Estática */}
          <div>
            <h3 className="text-sm font-semibold mb-3">Metadatos</h3>
            <div className="space-y-2 text-sm font-mono">
              <div className="flex justify-between">
                <p className="text-muted-foreground">Tamaño</p>
                <p>{apiAnalysis ? (apiAnalysis.tamano_bytes / 1024).toFixed(1) : '2.4'} MB</p>
              </div>
              <div className="flex justify-between">
                <p className="text-muted-foreground">ID</p>
                <p>#{id}</p>
              </div>
            </div>
          </div>
        </div>

        {/* ÁREA CENTRAL: GRAFO (Renderizando solo estáticos) */}
        <div className="flex-1 flex flex-col relative">
          <div className="bg-card border-b border-border px-6 py-4 flex items-center gap-4">
            <Filter className="w-5 h-5 text-muted-foreground" />
            <input
              type="range" min="0" max="1" step="0.1"
              value={attentionFilter}
              onChange={(e) => setAttentionFilter(parseFloat(e.target.value))}
              className="flex-1 max-w-xs accent-primary"
            />
            <span className="text-sm font-mono bg-secondary px-2 py-1 rounded">
              {(attentionFilter * 100).toFixed(0)}%
            </span>
          </div>

          <div className="flex-1 bg-background relative">
            <svg className="w-full h-full">
              {/* Conexiones */}
              {filteredNodes.map(node =>
                node.calls?.map(targetId => { // Añadido optional chaining ?.
                  const target = filteredNodes.find(n => n.id === targetId);
                  if (!target) return null;
                  return (
                    <line key={`${node.id}-${targetId}`} x1={node.x} y1={node.y + 15} x2={target.x} y2={target.y + 15} stroke="#333" strokeWidth="2" />
                  );
                })
              )}

              {/* Nodos */}
              {filteredNodes.map(node => (
                <g key={node.id} onClick={() => setSelectedFunction(node)} className="cursor-pointer">
                  <circle
                    cx={node.x} cy={node.y + 15} r={selectedFunction?.id === node.id ? "22" : "18"}
                    fill={getNodeColor(node.attention)}
                    stroke={selectedFunction?.id === node.id ? '#fff' : 'none'}
                    strokeWidth="3"
                  />
                  <text x={node.x} y={node.y + 50} textAnchor="middle" fill="#E0E0E0" fontSize="12" className="font-mono font-medium">
                    {node.name}
                  </text>
                </g>
              ))}
            </svg>
          </div>
        </div>

        {/* PANEL DERECHO: INSPECTOR */}
        {selectedFunction && (
          <div className="w-96 bg-card border-l border-border p-6 overflow-y-auto">
             <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <Code className="w-5 h-5 text-primary" /> Inspector
              </h2>
              <button onClick={() => setSelectedFunction(null)} className="text-muted-foreground">✕</button>
            </div>
            <div className="space-y-4 font-mono text-sm">
                <p className="text-muted-foreground uppercase text-[10px]">Función seleccionada</p>
                <div className="bg-secondary p-3 rounded">{selectedFunction.name}</div>
                <p className="text-xs text-blue-400 mt-4">// Datos de la API cargados en consola</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}