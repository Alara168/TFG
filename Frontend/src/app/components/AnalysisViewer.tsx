import { useEffect, useState, useMemo } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Filter, Loader2, Cpu, HelpCircle, ShieldCheck, AlertTriangle } from 'lucide-react';
import { apiClient } from '../services/api.client';

const DESCRIPCIONES_CLASES: Record<string, string> = {
  "Benigno": "El software no presenta comportamientos maliciosos conocidos. Es seguro para el sistema.",
  "Intrusion": "Software diseñado para infiltrarse (Backdoors/Loaders) y mantener el control de un equipo de forma remota sin permiso.",
  "Financiero": "Programas que buscan robar datos bancarios, contraseñas o criptomonedas (Bankers, Rats y Stealers).",
  "Otros/Ransom": "Amenazas críticas como el Ransomware que secuestra archivos cifrándolos, o virus destructivos que dañan el sistema.",
  "Herramientas/Sistema": "Herramientas de administración o de hacking que pueden ser usadas para ataques o pruebas de penetración."
};

// Componente Tooltip Estilo Post-it
function PostItTooltip({ text, anchorRect }: { text: string, anchorRect: DOMRect | null }) {
  if (!anchorRect) return null;

  return createPortal(
    <div 
      style={{ 
        position: 'fixed', 
        top: anchorRect.top, 
        left: anchorRect.right + 20,
        zIndex: 9999,
        // Amarillo pálido tipo post-it técnico
        backgroundColor: '#fef3c7', 
      }}
      className="w-64 p-4 rounded-sm shadow-[5px_5px_15px_rgba(0,0,0,0.3)] border-l-4 border-yellow-500 animate-in fade-in slide-in-from-left-2 duration-200"
    >
      <div className="flex items-center gap-2 mb-2 border-b border-yellow-900/10 pb-1">
        <span className="text-[10px] font-black uppercase tracking-widest text-yellow-800">Nota</span>
      </div>
      <p className="text-[12px] leading-snug text-yellow-950 font-medium">
        {text}
      </p>
      {/* Flecha Post-it */}
      <div 
        className="absolute top-4 -left-2 w-0 h-0 
        border-t-[6px] border-t-transparent 
        border-r-[8px] border-r-yellow-500 
        border-b-[6px] border-b-transparent" 
      />
    </div>,
    document.body
  );
}

export function AnalysisViewer() {
  const navigate = useNavigate();
  const { id } = useParams();
  
  const [analysis, setAnalysis] = useState<any>(null);
  const [graphData, setGraphData] = useState<{nodes: any[], edges: any[]}>({ nodes: [], edges: [] });
  const [isLoading, setIsLoading] = useState(true);
  const [attentionFilter, setAttentionFilter] = useState(0.01);
  const [selectedAddress, setSelectedAddress] = useState<string | null>(null);
  const [dimensions, setDimensions] = useState({ width: window.innerWidth, height: window.innerHeight });

  // Estado para el hover
  const [hoveredClass, setHoveredClass] = useState<{ name: string, rect: DOMRect } | null>(null);

  useEffect(() => {
    const handleResize = () => setDimensions({ width: window.innerWidth, height: window.innerHeight });
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const scaleFactor = useMemo(() => {
    const base = dimensions.width / 1920;
    return Math.max(0.85, Math.min(base * 1.05, 1.05));
  }, [dimensions.width]);
  
  const getFontSize = (size: number) => `${size * scaleFactor}px`;

  const verdict = useMemo(() => {
    if (!analysis?.probabilidades_json) return { label: "Analizando...", color: "text-white", isMalware: false };
    const malwareProbs = Object.entries(analysis.probabilidades_json)
      .filter(([name]) => name !== "Benigno")
      .map(([name, value]: any) => ({ name, value }));

    const topThreat = malwareProbs.reduce((prev, current) => (prev.value > current.value) ? prev : current);

    if (topThreat.value >= 0.4) {
      return { label: topThreat.name, color: "text-red-500", isMalware: true };
    }
    return { label: "Benigno", color: "text-primary", isMalware: false };
  }, [analysis]);

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
  const nodeRadius = 38 * scaleFactor;
  const COLUMN_SPACING = availableWidth / (columns + 0.5);
  const ROW_SPACING = 180 * scaleFactor;

  const nodePositions = useMemo(() => {
    const positions = new Map();
    visibleNodes.forEach((node, i) => {
      const row = Math.floor(i / columns);
      const col = i % columns;
      const x = (row % 2 === 0) 
        ? (col * COLUMN_SPACING) + (COLUMN_SPACING/2)
        : ((columns - 1 - col) * COLUMN_SPACING) + (COLUMN_SPACING/2);
      const y = (row * ROW_SPACING) + 100;
      positions.set(node.id, { x, y });
    });
    return positions;
  }, [visibleNodes, columns, COLUMN_SPACING, ROW_SPACING]);

  const svgHeight = useMemo(() => {
    const rows = Math.ceil(visibleNodes.length / columns);
    return (rows * ROW_SPACING) + 120;
  }, [visibleNodes.length, columns, ROW_SPACING]);

  const getNodeColor = (score: number) => {
    if (score > 0.07) return "#ef4444"; 
    if (score > 0.03) return "#f97316"; 
    return "#3b82f6";                  
  };

  const selectedDetail = analysis?.detalles_funciones?.find((f: any) => f.direccion_memoria === selectedAddress);

  if (isLoading) return (
    <div className="h-screen bg-[#050505] flex items-center justify-center font-mono text-primary">
      <Loader2 className="w-10 h-10 animate-spin" />
    </div>
  );

  return (
    <div className="h-[100dvh] w-screen bg-[#050505] flex flex-col text-white overflow-hidden p-0 m-0">
      <header className="bg-card/40 border-b border-white/10 px-8 py-4 flex items-center justify-between z-40 shrink-0">
        <div className="flex items-center gap-5">
          <button onClick={() => navigate('/dashboard')} className="p-2 hover:bg-white/10 rounded-lg transition-all">
            <ArrowLeft style={{ width: getFontSize(22), height: getFontSize(22) }} />
          </button>
          <div>
            <h1 style={{ fontSize: getFontSize(18) }} className="font-black tracking-tight uppercase">
              {analysis?.nombre_fichero}
            </h1>
            <p style={{ fontSize: getFontSize(10) }} className="text-white/40 font-mono tracking-tighter">
              {analysis?.hash_sha256}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-6">
            <div className="text-right mr-4">
               <span style={{ fontSize: getFontSize(9) }} className="font-bold text-white/40 uppercase tracking-widest block">Veredicto Final</span>
               <span style={{ fontSize: getFontSize(24) }} className={`font-black uppercase tracking-tighter ${verdict.color}`}>
                 {verdict.label}
               </span>
            </div>
            <div className="flex items-center gap-2 bg-white/5 px-4 py-2 rounded-xl border border-white/10">
                {verdict.isMalware ? <AlertTriangle className="text-red-500 w-5 h-5" /> : <ShieldCheck className="text-primary w-5 h-5" />}
                <span style={{ fontSize: getFontSize(32) }} className={`font-black ${verdict.color}`}>
                  {(analysis?.confianza_global * 100).toFixed(1)}%
                </span>
            </div>
        </div>
      </header>

      <div className="flex-1 flex min-h-0 overflow-hidden relative">
        {/* PANEL IZQUIERDO */}
        <aside className="w-64 bg-card/20 border-r border-white/10 p-5 flex flex-col z-30 shrink-0 overflow-y-auto scrollbar-hide">
          <h3 style={{ fontSize: getFontSize(14) }} className="font-black uppercase tracking-widest mb-8 text-white/60">Análisis</h3>
          <div className="space-y-6 pb-4">
            {analysis?.probabilidades_json && Object.entries(analysis.probabilidades_json)
              .filter(([name]) => name !== "Benigno")
              .map(([name, value]: any) => (
              <div 
                key={name} 
                className="group relative cursor-help"
                onMouseEnter={(e) => setHoveredClass({ name, rect: e.currentTarget.getBoundingClientRect() })}
                onMouseLeave={() => setHoveredClass(null)}
              >
                <div className="flex justify-between items-end mb-1.5">
                  <div className="flex items-center gap-2">
                    <span style={{ fontSize: getFontSize(11) }} className="font-black uppercase text-white/80">{name}</span>
                    <HelpCircle style={{ width: getFontSize(13), height: getFontSize(13) }} className="text-white/20 group-hover:text-primary transition-colors" />
                  </div>
                  <span style={{ fontSize: getFontSize(16) }} className="font-mono font-black text-white">{(value * 100).toFixed(1)}%</span>
                </div>
                <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                  <div className="h-full bg-primary/80 transition-all duration-700" style={{ width: `${value * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
        </aside>

        {/* TOOLTIP PORTAL ESTILO POST-IT */}
        {hoveredClass && (
          <PostItTooltip 
            text={DESCRIPCIONES_CLASES[hoveredClass.name] || ""} 
            anchorRect={hoveredClass.rect} 
          />
        )}

        {/* CONTENEDOR DEL GRAFO */}
        <main className="flex-1 relative bg-[radial-gradient(circle_at_50%_50%,_#0a0a0a_0%,_#050505_100%)] overflow-y-auto overflow-x-hidden scrollbar-hide flex flex-col items-center">
          <div className="sticky top-4 left-4 z-20 self-start w-fit bg-[#111]/80 backdrop-blur-md border border-white/10 p-4 rounded-xl ml-4 shrink-0">
            <div className="flex items-center gap-3">
              <Filter style={{ width: getFontSize(16), height: getFontSize(16) }} className="text-primary" />
              <input 
                type="range" min="0.005" max="0.1" step="0.005" 
                value={attentionFilter} 
                onChange={(e) => setAttentionFilter(parseFloat(e.target.value))}
                className="w-32 h-1 bg-white/10 rounded-lg appearance-none cursor-pointer accent-primary"
              />
              <span style={{ fontSize: getFontSize(14) }} className="font-black font-mono text-primary">{(attentionFilter).toFixed(3)}</span>
            </div>
          </div>

          <div className="flex-1 w-full flex items-start justify-center py-10">
            <svg width={availableWidth} height={svgHeight} className="overflow-visible">
              <defs>
                <marker id="arrowhead" markerWidth="8" markerHeight="6" refX={nodeRadius + 8} refY="3" orient="auto">
                  <polygon points="0 0, 8 3, 0 6" fill="rgba(255,255,255,0.2)" />
                </marker>
              </defs>

              {graphData.edges.map((edge, i) => {
                const start = nodePositions.get(edge.source);
                const end = nodePositions.get(edge.target);
                if (!start || !end) return null;
                return (
                  <line 
                    key={`edge-${i}`} x1={start.x} y1={start.y} x2={end.x} y2={end.y} 
                    stroke="rgba(255,255,255,0.1)" strokeWidth="1.5" markerEnd="url(#arrowhead)" 
                  />
                );
              })}

              {visibleNodes.map((node) => {
                const pos = nodePositions.get(node.id);
                if (!pos) return null;
                const isSelected = selectedAddress === node.id;
                const cleanLabel = node.label.replace(/^func_/i, '');
                
                return (
                  <g key={node.id} transform={`translate(${pos.x}, ${pos.y})`} 
                     onClick={() => setSelectedAddress(node.id)} className="cursor-pointer group">
                    <circle 
                      r={nodeRadius} 
                      fill={getNodeColor(node.atencion_score)} 
                      className="transition-all duration-300 group-hover:brightness-125"
                      stroke={isSelected ? "#fff" : "rgba(255,255,255,0.1)"}
                      strokeWidth={isSelected ? "3" : "1.5"}
                    />
                    <text y="4" textAnchor="middle" fill="#fff" 
                      style={{ fontSize: getFontSize(10) }} className="font-black font-mono pointer-events-none uppercase">
                      {cleanLabel.length > 8 ? cleanLabel.substring(0, 6) + '..' : cleanLabel}
                    </text>
                    <text y={nodeRadius + 18} textAnchor="middle" fill={isSelected ? "#fff" : "rgba(255,255,255,0.4)"} 
                      style={{ fontSize: getFontSize(9) }} className="font-bold font-mono uppercase tracking-tight">
                      {node.id.substring(2, 10)}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </main>

        {/* INSPECTOR DERECHO */}
        {selectedAddress && (
          <aside className="w-72 bg-card border-l border-white/10 p-6 z-40 shrink-0 overflow-y-auto scrollbar-hide">
            <div className="flex items-center justify-between mb-8">
              <h3 style={{ fontSize: getFontSize(16) }} className="flex items-center gap-2 font-black uppercase tracking-tight">
                <Cpu style={{ width: getFontSize(18), height: getFontSize(18) }} className="text-primary" /> Detalles
              </h3>
              <button onClick={() => setSelectedAddress(null)} className="text-white/40 hover:text-white">✕</button>
            </div>
            <div className="space-y-8">
              <div className="bg-white/5 p-4 rounded-xl border border-white/10">
                <span style={{ fontSize: getFontSize(9) }} className="text-primary font-black uppercase tracking-widest block mb-1.5">Dirección</span>
                <code style={{ fontSize: getFontSize(13) }} className="font-mono break-all leading-none">{selectedAddress}</code>
              </div>
              <div>
                <span style={{ fontSize: getFontSize(9) }} className="text-white/40 font-black uppercase tracking-widest block mb-1">Atención</span>
                <p style={{ fontSize: getFontSize(36) }} className="font-black tracking-tighter">{selectedDetail?.atencion_score.toFixed(5)}</p>
              </div>
              <div className="space-y-4">
                <span style={{ fontSize: getFontSize(9) }} className="text-white/40 font-black uppercase tracking-widest block border-b border-white/5 pb-1.5">Predicciones</span>
                {selectedDetail?.prediccion_especifica && Object.entries(selectedDetail.prediccion_especifica)
                  .map(([clase, val]: any) => (
                  <div key={clase} className="p-3 bg-white/5 rounded-xl border border-white/5">
                    <div className="flex justify-between font-black mb-1.5 uppercase" style={{ fontSize: getFontSize(10) }}>
                      <span>{clase}</span>
                      <span className="text-primary">{(val * 100).toFixed(1)}%</span>
                    </div>
                    <div className="h-1 bg-white/10 rounded-full overflow-hidden">
                      <div className="h-full bg-primary/60" style={{ width: `${val * 100}%` }} />
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