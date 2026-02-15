import { useEffect, useState, useMemo } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Filter, Loader2, Cpu, HelpCircle } from 'lucide-react';
import { apiClient } from '../services/api.client';

const DESCRIPCIONES_CLASES: Record<string, string> = {
  "Benigno": "El software no presenta comportamientos maliciosos conocidos. Es seguro para el sistema.",
  "Intrusion": "Software diseñado para infiltrarse (Backdoors/Loaders) y mantener el control de un equipo de forma remota sin permiso.",
  "Financiero": "Programas que buscan robar datos bancarios, contraseñas o criptomonedas (Bankers, Rats y Stealers).",
  "Otros/Ransom": "Amenazas críticas como el Ransomware que secuestra archivos cifrándolos, o virus destructivos que dañan el sistema.",
  "Herramientas/Sistema": "Herramientas de administración o de hacking que pueden ser usadas para ataques o pruebas de penetración."
};

export function AnalysisViewer() {
  const navigate = useNavigate();
  const { id } = useParams();
  
  const [analysis, setAnalysis] = useState<any>(null);
  const [graphData, setGraphData] = useState<{nodes: any[], edges: any[]}>({ nodes: [], edges: [] });
  const [isLoading, setIsLoading] = useState(true);
  const [attentionFilter, setAttentionFilter] = useState(0.01);
  const [selectedAddress, setSelectedAddress] = useState<string | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      if (!id) return;
      setIsLoading(true);
      try {
        const [resDetail, resGraph] = await Promise.all([
          apiClient(`/analisis/${id}/`),
          apiClient(`/analisis/${id}/grafo/`)
        ]);
        if (resDetail.ok) setAnalysis(await resDetail.json());
        if (resGraph.ok) setGraphData(await resGraph.json());
      } catch (err) { console.error("Error:", err); }
      finally { setIsLoading(false); }
    };
    fetchData();
  }, [id]);

  const [dimensions, setDimensions] = useState({ width: window.innerWidth, height: window.innerHeight });

  useEffect(() => {
    const handleResize = () => setDimensions({ width: window.innerWidth, height: window.innerHeight });
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const availableWidth = useMemo(() => {
    let w = dimensions.width - 288; 
    if (selectedAddress) w -= 320;  
    return w;
  }, [dimensions.width, selectedAddress]);

  const columns = useMemo(() => {
    if (availableWidth > 1400) return 5;
    if (availableWidth > 1000) return 4;
    if (availableWidth > 600) return 2;
    return 1;
  }, [availableWidth]);

  const visibleNodes = graphData.nodes.filter(n => n.atencion_score >= attentionFilter);
  const nodeRadius = 45; 
  const COLUMN_SPACING = availableWidth / (columns + 0.5);
  const ROW_SPACING = 220;

  const nodePositions = useMemo(() => {
    const positions = new Map();
    visibleNodes.forEach((node, i) => {
      const row = Math.floor(i / columns);
      const col = i % columns;
      const x = (row % 2 === 0) 
        ? (col * COLUMN_SPACING) + (COLUMN_SPACING/2)
        : ((columns - 1 - col) * COLUMN_SPACING) + (COLUMN_SPACING/2);
      const y = (row * ROW_SPACING) + 120;
      positions.set(node.id, { x, y });
    });
    return positions;
  }, [visibleNodes, columns, COLUMN_SPACING]);

  const svgHeight = useMemo(() => {
    const rows = Math.ceil(visibleNodes.length / columns);
    return (rows * ROW_SPACING) + 150;
  }, [visibleNodes.length, columns]);

  const getNodeColor = (score: number) => {
    if (score > 0.07) return "#ef4444"; 
    if (score > 0.03) return "#f97316"; 
    return "#3b82f6";                  
  };

  const selectedDetail = analysis?.detalles_funciones?.find((f: any) => f.direccion_memoria === selectedAddress);

  if (isLoading) return (
    <div className="h-screen bg-[#050505] flex items-center justify-center font-mono text-primary">
      <Loader2 className="w-12 h-12 animate-spin" />
    </div>
  );

  return (
    <div className="h-[100dvh] w-screen bg-[#050505] flex flex-col text-white overflow-hidden p-0 m-0 border-none">
      {/* HEADER */}
      <header className="bg-card/40 border-b border-white/10 px-8 py-5 flex items-center justify-between z-40 shrink-0">
        <div className="flex items-center gap-6">
          <button onClick={() => navigate('/dashboard')} className="p-2 hover:bg-white/10 rounded-lg transition-all">
            <ArrowLeft className="w-7 h-7" />
          </button>
          <div>
            <h1 className="text-2xl font-black tracking-tight uppercase">{analysis?.nombre_fichero}</h1>
            <p className="text-xs text-white/40 font-mono">{analysis?.hash_sha256}</p>
          </div>
        </div>
        <div className="flex items-center gap-6">
            <span className="text-xs font-bold text-white/40 uppercase tracking-widest">Confianza Global</span>
            <span className="text-4xl font-black text-primary">{(analysis?.confianza_global * 100).toFixed(1)}%</span>
        </div>
      </header>

      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* PANEL IZQUIERDO */}
        <aside className="w-72 bg-card/20 border-r border-white/10 p-6 flex flex-col z-30 shrink-0 overflow-y-auto scrollbar-hide">
          <h3 className="text-lg font-black uppercase tracking-tighter mb-10 text-white/80">Resultado Análisis</h3>
          <div className="space-y-8 pb-4">
            {analysis?.probabilidades_json && Object.entries(analysis.probabilidades_json).map(([name, value]: any) => (
              <div key={name} className="group relative">
                <div className="flex justify-between items-end mb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-black uppercase text-white/90">{name}</span>
                    <div className="static">
                      <HelpCircle className="w-4 h-4 text-white/20 hover:text-primary cursor-help" />
                      <div className="fixed left-[290px] mt-[-20px] w-72 p-5 bg-white text-black text-sm rounded-2xl shadow-[0_20px_60px_rgba(0,0,0,0.7)] opacity-0 group-hover:opacity-100 pointer-events-none transition-all z-[100] font-medium border border-black/5">
                        <div className="font-black mb-2 border-b border-black/10 pb-1 uppercase text-xs tracking-widest text-primary">{name}</div>
                        {DESCRIPCIONES_CLASES[name] || "Descripción técnica no disponible."}
                      </div>
                    </div>
                  </div>
                  <span className="text-2xl font-mono font-black">{(value * 100).toFixed(1)}%</span>
                </div>
                <div className="h-2.5 bg-white/5 rounded-full overflow-hidden border border-white/5">
                  <div className="h-full bg-primary transition-all duration-700 shadow-[0_0_10px_#22c55e]" style={{ width: `${value * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
        </aside>

        {/* CONTENEDOR DEL GRAFO - TOTALMENTE CONTROLADO */}
        <main className="flex-1 relative bg-[radial-gradient(circle_at_50%_50%,_#111_0%,_#050505_100%)] overflow-y-auto overflow-x-hidden scrollbar-hide p-0 flex flex-col items-center min-h-0">
          <div className="sticky top-6 left-6 z-20 self-start w-fit bg-[#111]/90 backdrop-blur-xl border border-white/10 p-5 rounded-2xl shadow-2xl ml-6 shrink-0">
            <div className="flex items-center gap-4">
              <Filter className="w-5 h-5 text-primary" />
              <input 
                type="range" min="0.005" max="0.1" step="0.005" 
                value={attentionFilter} 
                onChange={(e) => setAttentionFilter(parseFloat(e.target.value))}
                className="w-40 h-1.5 bg-white/10 rounded-lg appearance-none cursor-pointer accent-primary"
              />
              <span className="text-xl font-black font-mono text-primary">{(attentionFilter).toFixed(3)}</span>
            </div>
          </div>

          <div className="flex-1 w-full min-h-0 flex items-start justify-center">
            <svg 
              width={availableWidth} 
              height={svgHeight} 
              className="block overflow-visible shrink-0 transition-all duration-500 m-0 p-0"
              style={{ minHeight: svgHeight }}
            >
              <defs>
                <marker id="arrowhead" markerWidth="10" markerHeight="7" refX={nodeRadius + 10} refY="3.5" orient="auto">
                  <polygon points="0 0, 10 3.5, 0 7" fill="rgba(255,255,255,0.4)" />
                </marker>
              </defs>

              {graphData.edges.map((edge, i) => {
                const start = nodePositions.get(edge.source);
                const end = nodePositions.get(edge.target);
                if (!start || !end) return null;
                return (
                  <line 
                    key={`edge-${i}`} x1={start.x} y1={start.y} x2={end.x} y2={end.y} 
                    stroke="rgba(255,255,255,0.15)" strokeWidth="3" markerEnd="url(#arrowhead)" 
                    className="transition-all duration-500"
                  />
                );
              })}

              {visibleNodes.map((node) => {
                const pos = nodePositions.get(node.id);
                if (!pos) return null;
                const isSelected = selectedAddress === node.id;
                
                return (
                  <g key={node.id} transform={`translate(${pos.x}, ${pos.y})`} 
                     onClick={() => setSelectedAddress(node.id)} className="cursor-pointer group transition-all duration-500">
                    <circle 
                      r={nodeRadius} 
                      fill={getNodeColor(node.atencion_score)} 
                      className="transition-all duration-300 group-hover:scale-110 group-hover:brightness-125"
                      stroke={isSelected ? "#fff" : "rgba(255,255,255,0.15)"}
                      strokeWidth={isSelected ? "5" : "2"}
                    />
                    <text y="5" textAnchor="middle" fill="#fff" className="text-[12px] font-black font-mono pointer-events-none uppercase">
                      {node.label.length > 10 ? node.label.substring(0, 8) + '..' : node.label}
                    </text>
                    <text y={nodeRadius + 25} textAnchor="middle" fill={isSelected ? "#fff" : "rgba(255,255,255,0.5)"} className="text-[11px] font-bold font-mono uppercase tracking-tighter">
                      {node.id.substring(2, 12)}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </main>

        {/* INSPECTOR DERECHO */}
        {selectedAddress && (
          <aside className="w-80 bg-card border-l border-white/10 p-8 z-40 animate-in slide-in-from-right shrink-0 overflow-y-auto scrollbar-hide">
            <div className="flex items-center justify-between mb-10">
              <h3 className="flex items-center gap-3 text-xl font-black uppercase tracking-tighter">
                <Cpu className="w-6 h-6 text-primary" /> Detalles
              </h3>
              <button onClick={() => setSelectedAddress(null)} className="p-2 hover:bg-white/10 rounded-full text-white/40 hover:text-white">✕</button>
            </div>
            <div className="space-y-10 pb-6">
              <div className="bg-white/5 p-5 rounded-2xl border border-white/10">
                <span className="text-[10px] text-primary font-black uppercase tracking-widest block mb-2">Memoria</span>
                <code className="text-base font-mono break-all leading-tight">{selectedAddress}</code>
              </div>
              <div>
                <span className="text-[10px] text-white/40 font-black uppercase tracking-widest block mb-2">Atención IA</span>
                <p className="text-5xl font-black tracking-tighter">{selectedDetail?.atencion_score.toFixed(5)}</p>
              </div>
              <div className="space-y-5">
                <span className="text-[10px] text-white/40 font-black uppercase tracking-widest block border-b border-white/5 pb-2">Probabilidades</span>
                {selectedDetail?.prediccion_especifica && Object.entries(selectedDetail.prediccion_especifica).map(([clase, val]: any) => (
                  <div key={clase} className="p-4 bg-white/5 rounded-2xl border border-white/5">
                    <div className="flex justify-between text-xs font-black mb-2 uppercase">
                      <span>{clase}</span>
                      <span className="text-primary">{(val * 100).toFixed(1)}%</span>
                    </div>
                    <div className="h-1.5 bg-white/10 rounded-full overflow-hidden">
                      <div className="h-full bg-primary/50" style={{ width: `${val * 100}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}