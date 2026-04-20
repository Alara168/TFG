import { useEffect, useState, useMemo, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Filter, Loader2, Cpu, HelpCircle, ShieldCheck, AlertTriangle, LogOut, FileText, Download, Table } from 'lucide-react';
import { apiClient } from '../services/api.client';
import { authService } from '../services/auth.service';
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';

// --- CONFIGURACIÓN DE TEXTOS EDUCATIVOS PARA EL PDF ---
const DESCRIPCIONES_CLASES: Record<string, string> = {
  "Benigno": "El software no presenta comportamientos maliciosos conocidos. Es seguro para el sistema.",
  "Intrusion": "Software diseñado para infiltrarse (Backdoors/Loaders) y mantener el control de un equipo de forma remota sin permiso.",
  "Financiero": "Programas que buscan robar datos bancarios, contraseñas o criptomonedas (Bankers, Rats y Stealers).",
  "Otros/Ransom": "Amenazas críticas como el Ransomware que secuestra archivos cifrándolos, o virus destructivos que dañan el sistema.",
  "Herramientas/Sistema": "Herramientas de administración o de hacking que pueden ser usadas para ataques o pruebas de penetración."
};

const DESCRIPCION_ATENCION = "La puntuación de atención indica qué tan relevante es esta función para la decisión final del modelo. Un valor alto significa que el código de esta función contiene patrones críticos que definen el comportamiento malicioso o benigno.";

const GLOSARIO_ATENCION = "La 'Atención Neuronal' es una técnica de IA que permite al modelo resaltar qué partes del código (funciones) han sido determinantes para su decisión. Una puntuación alta significa que esa función contiene patrones de comportamiento altamente característicos de su categoría.";

const METODOLOGIA = "Este análisis se basa en el examen de las Atenciones de una red neuronal profunda que procesa el grafo de flujo de control del binario, permitiendo detectar amenazas incluso si el código ha sido ofuscado.";

// --- UTILIDADES ---
const exportData = (data: any, type: 'json' | 'csv', filename: string) => {
  let content = "";
  let contentType = "";
  filename = filename + `_${new Date().toISOString().slice(0, 10)}`

  if (type === 'json') {
    content = JSON.stringify(data, null, 2);
    contentType = 'application/json';
  } else {
    if (!data || data.length === 0) return;
    const flattenedData = data.map((item: any) => {
      const { prediccion_especifica, ...rest } = item;
      return { ...rest, ...prediccion_especifica };
    });
    const headers = Object.keys(flattenedData[0]);
    const rows = flattenedData.map((obj: any) => 
      headers.map(header => {
        const value = obj[header];
        return typeof value === 'number' ? value.toFixed(6) : `"${value}"`;
      }).join(';')
    );
    content = [headers.join(';'), ...rows].join('\n');
    contentType = 'text/csv';
  }

  const blob = new Blob([content], { type: contentType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${filename}.${type}`;
  link.click();
  URL.revokeObjectURL(url);
};

function PostItTooltip({ text, anchorRect }: { text: string, anchorRect: DOMRect | null }) {
  if (!anchorRect) return null;
  const isRightSide = anchorRect.left > window.innerWidth / 2;
  return createPortal(
    <div 
      style={{ position: 'fixed', top: anchorRect.top, left: isRightSide ? 'auto' : anchorRect.right + 20, right: isRightSide ? (window.innerWidth - anchorRect.left) + 20 : 'auto', zIndex: 9999, backgroundColor: '#fef3c7' }}
      className="w-64 p-4 rounded-sm shadow-[5px_5px_15px_rgba(0,0,0,0.3)] border-l-4 border-yellow-500 animate-in fade-in slide-in-from-left-2 duration-200"
    >
      <div className="flex items-center gap-2 mb-2 border-b border-yellow-900/10 pb-1">
        <span className="text-[10px] font-black uppercase tracking-widest text-yellow-800">Nota Informativa</span>
      </div>
      <p className="text-[12px] leading-snug text-yellow-950 font-medium">{text}</p>
    </div>,
    document.body
  );
}

// --- COMPONENTE PRINCIPAL ---
export function AnalysisViewer() {
  const navigate = useNavigate();
  const { id } = useParams();
  const graphRef = useRef<HTMLDivElement>(null);
  const [analysis, setAnalysis] = useState<any>(null);
  const [graphData, setGraphData] = useState<{nodes: any[], edges: any[]}>({ nodes: [], edges: [] });
  const [isLoading, setIsLoading] = useState(true);
  const [isExporting, setIsExporting] = useState(false);
  const [attentionFilter, setAttentionFilter] = useState(0);
  const [selectedAddress, setSelectedAddress] = useState<string | null>(null);
  const [dimensions, setDimensions] = useState({ width: window.innerWidth, height: window.innerHeight });
  const [codeData, setCodeData] = useState<string | null>(null);
  const [isCodeLoading, setIsCodeLoading] = useState(false);
  const [activeTooltip, setActiveTooltip] = useState<{ text: string, rect: DOMRect } | null>(null);

  useEffect(() => {
    const handleResize = () => setDimensions({ width: window.innerWidth, height: window.innerHeight });
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    setCodeData(null);
  }, [selectedAddress]);

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

  const handleExportPDF = async () => {
    if (isExporting || !graphRef.current) return;
    setIsExporting(true);

    try {
      const doc = new jsPDF('p', 'mm', 'a4');
      const pageWidth = doc.internal.pageSize.getWidth();
      const pageHeight = doc.internal.pageSize.getHeight();
      const margin = 20;
      let currentY = 20;

      // --- 1. ENCABEZADO ESTILIZADO ---
      doc.setFillColor(15, 15, 15);
      doc.rect(0, 0, pageWidth, 40, 'F');
      doc.setTextColor(255, 255, 255);
      doc.setFontSize(18);
      doc.setFont("helvetica", "bold");
      doc.text("INFORME DE ANÁLISIS DE BINARIOS", margin, 20);
      
      doc.setFontSize(9);
      doc.setFont("helvetica", "normal");
      doc.text(`ID de Análisis: ${id}`, margin, 28);
      doc.text(`Fecha de Generación: ${new Date().toLocaleString()}`, margin, 33);

      // --- 2. RESUMEN EJECUTIVO ---
      currentY = 55;
      doc.setTextColor(40, 40, 40);
      doc.setFontSize(14);
      doc.setFont("helvetica", "bold");
      doc.text("1. Resumen Ejecutivo", margin, currentY);
      doc.line(margin, currentY + 2, pageWidth - margin, currentY + 2);
      
      currentY += 12;
      doc.setFontSize(10);
      const summaryData = [
        ["Nombre del Fichero:", analysis?.nombre_fichero || "N/A"],
        ["Hash SHA-256:", analysis?.hash_sha256 || "N/A"],
        ["Veredicto Final:", verdict.label.toUpperCase()],
        ["Confianza Global:", `${(analysis?.confianza_global * 100).toFixed(1)}%`]
      ];

      summaryData.forEach(([label, value]) => {
        doc.setFont("helvetica", "bold");
        doc.text(label, margin, currentY);
        doc.setFont("helvetica", "normal");
        doc.text(String(value), 65, currentY);
        currentY += 7;
      });

      // --- 3. CONCEPTOS CLAVE Y METODOLOGÍA (EDUCATIVO) ---
      currentY += 10;
      doc.setFontSize(14);
      doc.setFont("helvetica", "bold");
      doc.text("2. Conceptos Clave y Metodología", margin, currentY);
      doc.line(margin, currentY + 2, pageWidth - margin, currentY + 2);
      
      currentY += 10;
      doc.setFontSize(10);
      doc.setFont("helvetica", "bold");
      doc.text("¿Qué es la Atención Neuronal?", margin, currentY);
      
      currentY += 5;
      doc.setFont("helvetica", "normal");
      const splitAtencion = doc.splitTextToSize(GLOSARIO_ATENCION, pageWidth - (margin * 2));
      doc.text(splitAtencion, margin, currentY);
      currentY += (splitAtencion.length * 5) + 10;

      doc.setFont("helvetica", "bold");
      doc.text("Definición de Categorías de Análisis:", margin, currentY);
      currentY += 7;

      // RENDERIZADO CORREGIDO: "Categoría: Descripción"
      Object.entries(DESCRIPCIONES_CLASES).forEach(([clase, desc]) => {
        // Verificar si nos quedamos sin espacio en la página
        if (currentY > pageHeight - 20) {
          doc.addPage();
          currentY = 20;
        }

        doc.setFontSize(9);
        doc.setFont("helvetica", "bold");
        const categoriaLabel = `${clase}: `;
        doc.text(categoriaLabel, margin + 2, currentY);
        
        // Calcular inicio del texto de descripción
        const labelWidth = doc.getTextWidth(categoriaLabel);
        
        doc.setFont("helvetica", "normal");
        const descMaxWidth = pageWidth - (margin * 2) - labelWidth - 5;
        const splitDesc = doc.splitTextToSize(desc, descMaxWidth);
        
        doc.text(splitDesc, margin + 2 + labelWidth, currentY);
        
        // Espaciado proporcional al número de líneas de la descripción
        currentY += (splitDesc.length * 4.5) + 3;
      });

      // --- 4. VISUALIZACIÓN DEL GRAFO ---
      doc.addPage();
      currentY = 20;
      doc.setTextColor(40, 40, 40);
      doc.setFontSize(14);
      doc.setFont("helvetica", "bold");
      doc.text("3. Visualización del Grafo de Atenciones", margin, currentY);
      doc.line(margin, currentY + 2, pageWidth - margin, currentY + 2);
      
      // Captura del componente visual (SVG/Grafo)
      const canvas = await html2canvas(graphRef.current, {
        backgroundColor: '#050505',
        scale: 2,
        logging: false,
        useCORS: true
      });
      
      const imgData = canvas.toDataURL('image/png');
      const imgWidth = pageWidth - (margin * 2);
      const imgHeight = (canvas.height * imgWidth) / canvas.width;
      
      // Ajustar imagen para que no exceda la página
      const maxImgHeight = 150;
      const finalImgHeight = Math.min(imgHeight, maxImgHeight);
      
      doc.addImage(imgData, 'PNG', margin, currentY + 10, imgWidth, finalImgHeight);
      currentY += finalImgHeight + 25;

      // --- 5. DESGLOSE TÉCNICO DE FUNCIONES ---
      if (analysis?.detalles_funciones && analysis.detalles_funciones.length > 0) {
        // Si queda poco espacio, saltar página
        if (currentY > pageHeight - 40) {
          doc.addPage();
          currentY = 20;
        }

        doc.setFontSize(14);
        doc.setFont("helvetica", "bold");
        doc.text("4. Desglose de Funciones de Alta Relevancia", margin, currentY);
        doc.line(margin, currentY + 2, pageWidth - margin, currentY + 2);
        currentY += 12;

        analysis.detalles_funciones.forEach((func: any) => {
          if (currentY > pageHeight - 25) {
            doc.addPage();
            currentY = 20;
          }

          doc.setFontSize(10);
          doc.setFont("helvetica", "bold");
          doc.text(`Dirección de Memoria: ${func.direccion_memoria}`, margin, currentY);
          
          doc.setFont("helvetica", "normal");
          doc.text(`Nivel de Atención: ${func.atencion_score.toFixed(6)}`, 125, currentY);
          
          currentY += 6;
          // Mostrar predicciones específicas de la función
          const predicciones = Object.entries(func.prediccion_especifica)
            .map(([k, v]: any) => `${k}: ${(v * 100).toFixed(1)}%`)
            .join("  |  ");
          
          doc.setFontSize(8);
          doc.setTextColor(100, 100, 100);
          doc.text(predicciones, margin + 5, currentY);
          
          currentY += 8;
          doc.setDrawColor(230, 230, 230);
          doc.line(margin, currentY - 4, pageWidth - margin, currentY - 4);
          doc.setTextColor(40, 40, 40);
        });
      }

      // --- GUARDAR ARCHIVO ---
      const fileName = analysis?.nombre_fichero 
        ? `Reporte_Tecnico_${analysis.nombre_fichero.replace(/\.[^/.]+$/, "")}.pdf`
        : "Reporte_Analisis_IA.pdf";
        
      doc.save(fileName);

    } catch (error) {
      console.error("Error al exportar PDF:", error);
      alert("Hubo un error al generar el reporte PDF.");
    } finally {
      setIsExporting(false);
    }
  };

  const fetchFunctionCode = async () => {
    if (!selectedAddress || !id) return;
    setIsCodeLoading(true);
    try {
      const res = await apiClient(`/analisis/${id}/codigo/${selectedAddress}/`);
      if (res.ok) { setCodeData((await res.json()).codigo); }
    } catch (err) { console.error("Error:", err); }
    finally { setIsCodeLoading(false); }
  };

  const scaleFactor = useMemo(() => {
    const base = dimensions.width / 1920;
    return Math.max(0.85, Math.min(base * 1.05, 1.05));
  }, [dimensions.width]);
  
  const getFontSize = (size: number) => `${size * scaleFactor}px`;

  const verdict = useMemo(() => {
    if (!analysis?.probabilidades_json) return { label: "Analizando...", color: "text-white", isMalware: false };
    const malwareProbs = Object.entries(analysis.probabilidades_json).filter(([n]) => n !== "Benigno").map(([n, v]: any) => ({ n, v }));
    const topThreat = malwareProbs.reduce((p, c) => (p.v > c.v) ? p : c);
    if (topThreat.v >= 0.4) return { label: topThreat.n, color: "text-red-500", isMalware: true };
    return { label: "Benigno", color: "text-primary", isMalware: false };
  }, [analysis]);

  const availableWidth = useMemo(() => {
    let w = dimensions.width - 288; 
    if (selectedAddress) w -= 320;  
    return w;
  }, [dimensions.width, selectedAddress]);

  const columns = useMemo(() => {
    if (availableWidth > 1400) return 5;
    if (availableWidth > 1000) return 4;
    return availableWidth > 600 ? 2 : 1;
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
      const x = (row % 2 === 0) ? (col * COLUMN_SPACING) + (COLUMN_SPACING/2) : ((columns - 1 - col) * COLUMN_SPACING) + (COLUMN_SPACING/2);
      const y = (row * ROW_SPACING) + 100;
      positions.set(node.id, { x, y });
    });
    return positions;
  }, [visibleNodes, columns, COLUMN_SPACING, ROW_SPACING]);

  const svgHeight = useMemo(() => Math.ceil(visibleNodes.length / columns) * ROW_SPACING + 120, [visibleNodes.length, columns, ROW_SPACING]);

  const selectedDetail = analysis?.detalles_funciones?.find((f: any) => f.direccion_memoria === selectedAddress);

  if (isLoading) return <div className="h-screen bg-[#050505] flex items-center justify-center font-mono text-primary"><Loader2 className="w-10 h-10 animate-spin" /></div>;

  return (
    <div className="h-[100dvh] w-screen bg-[#050505] flex flex-col text-white overflow-hidden">
      <header className="bg-card/40 border-b border-white/10 px-8 py-4 flex items-center justify-between z-40 shrink-0">
        <div className="flex items-center gap-5">
          <button onClick={() => navigate('/dashboard')} className="p-2 hover:bg-white/10 rounded-lg transition-all"><ArrowLeft style={{ width: getFontSize(22), height: getFontSize(22) }} /></button>
          <div>
            <h1 style={{ fontSize: getFontSize(18) }} className="font-black tracking-tight uppercase">Grafo de Dependencias: {analysis?.nombre_fichero}</h1>
            <p style={{ fontSize: getFontSize(10) }} className="text-white/40 font-mono tracking-tighter">{analysis?.hash_sha256}</p>
          </div>
        </div>

        <div className="flex gap-2">
          <button onClick={() => exportData(analysis, 'json', analysis?.nombre_fichero)} className="text-xs bg-white/5 border border-white/10 px-3 py-1.5 rounded hover:bg-white/10 flex items-center gap-2"><Download className="w-3 h-3" /> JSON</button>
          <button onClick={() => exportData(analysis?.detalles_funciones, 'csv', analysis?.nombre_fichero)} className="text-xs bg-white/5 border border-white/10 px-3 py-1.5 rounded hover:bg-white/10 flex items-center gap-2"><Table className="w-3 h-3" /> CSV</button>
          <button onClick={handleExportPDF} disabled={isExporting} className="text-xs bg-primary text-primary-foreground font-black px-4 py-1.5 rounded hover:brightness-110 flex items-center gap-2 disabled:opacity-50">
            {isExporting ? <Loader2 className="w-3 h-3 animate-spin" /> : <FileText className="w-3 h-3" />} PDF REPORT
          </button>
        </div>

        <div className="flex items-center gap-8">
          <div className="text-right">
            <span style={{ fontSize: getFontSize(9) }} className="font-bold text-white/40 uppercase tracking-widest block">Veredicto Final</span>
            <span style={{ fontSize: getFontSize(24) }} className={`font-black uppercase tracking-tighter ${verdict.color}`}>{verdict.label}</span>
          </div>
          <div className="flex items-center gap-2 bg-white/5 px-4 py-2 rounded-xl border border-white/10">
            {verdict.isMalware ? <AlertTriangle className="text-red-500 w-5 h-5" /> : <ShieldCheck className="text-primary w-5 h-5" />}
            <span style={{ fontSize: getFontSize(32) }} className={`font-black ${verdict.color}`}>{(analysis?.confianza_global * 100).toFixed(1)}%</span>
          </div>
          <button onClick={() => authService.logout()} className="bg-secondary text-secondary-foreground px-4 py-2 rounded-md border border-white/10 text-xs font-bold flex items-center gap-2"><LogOut className="w-4 h-4" /> Salir</button>
        </div>
      </header>

      <div className="flex-1 flex min-h-0 overflow-hidden relative">
        <aside className="w-64 bg-card/20 border-r border-white/10 p-5 flex flex-col z-30 shrink-0 overflow-y-auto scrollbar-hide">
          <h3 style={{ fontSize: getFontSize(14) }} className="font-black uppercase tracking-widest mb-8 text-white/60">Análisis</h3>
          <div className="space-y-6 pb-8 border-b border-white/10 mb-8">
            {analysis?.probabilidades_json && Object.entries(analysis.probabilidades_json).filter(([n]) => n !== "Benigno").map(([name, value]: any) => (
              <div key={name} className="group relative cursor-help" onMouseEnter={(e) => setActiveTooltip({ text: DESCRIPCIONES_CLASES[name], rect: e.currentTarget.getBoundingClientRect() })} onMouseLeave={() => setActiveTooltip(null)}>
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
          <div className="space-y-4">
            <div className="flex items-center gap-2 mb-2"><Filter style={{ width: getFontSize(14), height: getFontSize(14) }} className="text-primary" /><span style={{ fontSize: getFontSize(10) }} className="font-black uppercase tracking-widest text-white/40">Filtro Atención</span></div>
            <input type="range" min="0" max="0.5" step="0.005" value={attentionFilter} onChange={(e) => setAttentionFilter(parseFloat(e.target.value))} className="w-full h-1.5 bg-white/10 rounded-lg appearance-none cursor-pointer accent-primary" />
            <div className="flex justify-between font-mono text-primary font-black" style={{ fontSize: getFontSize(14) }}><span>Umbral:</span><span>{(attentionFilter).toFixed(3)}</span></div>
          </div>
        </aside>

        {activeTooltip && <PostItTooltip text={activeTooltip.text} anchorRect={activeTooltip.rect} />}

        <main className="flex-1 relative bg-[radial-gradient(circle_at_50%_50%,_#0a0a0a_0%,_#050505_100%)] overflow-y-auto scrollbar-hide flex flex-col items-center">
          <div ref={graphRef} className="flex-1 w-full flex items-start justify-center py-10 min-h-fit">
            <svg width={availableWidth} height={svgHeight} className="overflow-visible">
              {graphData.edges.map((edge, i) => {
                const start = nodePositions.get(edge.source);
                const end = nodePositions.get(edge.target);
                if (!start || !end) return null;
                return <line key={`edge-${i}`} x1={start.x} y1={start.y} x2={end.x} y2={end.y} stroke="rgba(255,255,255,0.1)" strokeWidth="1.5" />;
              })}
              {visibleNodes.map((node) => {
                const pos = nodePositions.get(node.id);
                if (!pos) return null;
                const isSelected = selectedAddress === node.id;
                return (
                  <g key={node.id} transform={`translate(${pos.x}, ${pos.y})`} onClick={() => setSelectedAddress(node.id)} className="cursor-pointer group">
                    <circle r={nodeRadius} fill={node.atencion_score > 0.07 ? "#ef4444" : node.atencion_score > 0.03 ? "#f97316" : "#3b82f6"} className="transition-all duration-300 group-hover:brightness-125" stroke={isSelected ? "#fff" : "rgba(255,255,255,0.1)"} strokeWidth={isSelected ? "3" : "1.5"} />
                    <text y="4" textAnchor="middle" fill="#fff" style={{ fontSize: getFontSize(11) }} className="font-black font-mono pointer-events-none">{node.atencion_score.toFixed(3)}</text>
                    <text y={nodeRadius + 22} textAnchor="middle" fill={isSelected ? "#fff" : "rgba(255,255,255,0.5)"} style={{ fontSize: getFontSize(10) }} className="font-bold font-mono uppercase tracking-tighter">{node.id}</text>
                  </g>
                );
              })}
            </svg>
          </div>
        </main>

        {selectedAddress && (<aside className="w-80 bg-card border-l border-white/10 p-6 z-40 shrink-0 overflow-y-auto scrollbar-hide animate-in slide-in-from-right duration-300">
                {/* Cabecera de la barra lateral */}
                <div className="flex items-center justify-between mb-8">
                  <h3 style={{ fontSize: getFontSize(16) }} className="flex items-center gap-2 font-black uppercase tracking-tight">
                    <Cpu style={{ width: getFontSize(18), height: getFontSize(18) }} className="text-primary" /> 
                    Detalles
                  </h3>
                  <button 
                    onClick={() => setSelectedAddress(null)} 
                    className="p-1 hover:bg-white/10 rounded-md text-white/40 hover:text-white transition-colors"
                  >
                    ✕
                  </button>
                </div>

                <div className="space-y-8">
                  {/* Sección 1: Puntuación de Atención con Tooltip */}
                  <div>
                    <div 
                      className="flex items-center gap-2 mb-1 group/help cursor-help w-fit"
                      onMouseEnter={(e) => setActiveTooltip({ 
                        text: DESCRIPCION_ATENCION, 
                        rect: e.currentTarget.getBoundingClientRect() 
                      })}
                      onMouseLeave={() => setActiveTooltip(null)}
                    >
                      <span style={{ fontSize: getFontSize(9) }} className="text-white/40 font-black uppercase tracking-widest block">
                        Atención
                      </span>
                      <HelpCircle 
                        style={{ width: getFontSize(12), height: getFontSize(12) }} 
                        className="text-white/20 group-hover/help:text-primary transition-colors" 
                      />
                    </div>
                    <p style={{ fontSize: getFontSize(36) }} className="font-black tracking-tighter leading-none">
                      {selectedDetail?.atencion_score.toFixed(5)}
                    </p>
                  </div>

                  {/* Sección 2: Predicciones Específicas por Categoría */}
                  <div className="space-y-4">
                    <span style={{ fontSize: getFontSize(9) }} className="text-white/40 font-black uppercase tracking-widest block border-b border-white/5 pb-1.5">
                      Predicciones de Clase
                    </span>
                    
                    {selectedDetail?.prediccion_especifica && Object.entries(selectedDetail.prediccion_especifica).map(([clase, val]: any) => (
                      <div 
                        key={clase} 
                        className="p-3 bg-white/5 rounded-xl border border-white/5 group/row relative cursor-help hover:bg-white/[0.08] transition-colors"
                        onMouseEnter={(e) => setActiveTooltip({ 
                          text: DESCRIPCIONES_CLASES[clase] || "Sin descripción disponible", 
                          rect: e.currentTarget.getBoundingClientRect() 
                        })}
                        onMouseLeave={() => setActiveTooltip(null)}
                      >
                        <div className="flex justify-between font-black mb-2 uppercase" style={{ fontSize: getFontSize(10) }}>
                          <span className="text-white/70 group-hover/row:text-white transition-colors">{clase}</span>
                          <span className="text-primary">{(val * 100).toFixed(1)}%</span>
                        </div>
                        {/* Barra de progreso visual */}
                        <div className="h-1.5 bg-white/10 rounded-full overflow-hidden">
                          <div 
                            className="h-full bg-primary/60 transition-all duration-500" 
                            style={{ width: `${val * 100}%` }} 
                          />
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Sección 3: Información Técnica (Dirección de Memoria) */}
                  <div className="bg-white/5 p-4 rounded-xl border border-white/10 shadow-inner">
                    <span style={{ fontSize: getFontSize(9) }} className="text-primary font-black uppercase tracking-widest block mb-1.5">
                      Dirección de Memoria
                    </span>
                    <code style={{ fontSize: getFontSize(13) }} className="font-mono break-all leading-none text-white/90">
                      {selectedAddress}
                    </code>
                  </div>

                  {/* Sección 4: Desensamblado (ASM) */}
                  <div className="pt-4 border-t border-white/10">
                    {!codeData ? (
                      <button 
                        onClick={fetchFunctionCode} 
                        disabled={isCodeLoading} 
                        className="w-full py-3 bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20 rounded-xl font-black uppercase text-[11px] flex items-center justify-center gap-2 transition-all disabled:opacity-50"
                      >
                        {isCodeLoading ? (
                          <>
                            <Loader2 className="animate-spin w-4 h-4" />
                            Cargando...
                          </>
                        ) : (
                          "Ver Código Desensamblado"
                        )}
                      </button>
                    ) : (
                      <div className="space-y-3 animate-in fade-in slide-in-from-bottom-2 duration-300">
                        <div className="flex justify-between items-center">
                          <span style={{ fontSize: getFontSize(9) }} className="text-primary font-black uppercase tracking-widest">
                            Instrucciones ASM
                          </span>
                          <button 
                            onClick={() => setCodeData(null)} 
                            className="text-[10px] text-white/40 hover:text-white underline decoration-dotted transition-colors"
                          >
                            Ocultar
                          </button>
                        </div>
                        <pre className="bg-black/50 p-4 rounded-xl border border-white/5 font-mono text-[9px] text-emerald-400 overflow-x-auto max-h-96 scrollbar-thin scrollbar-thumb-white/10 shadow-inner leading-relaxed">
                          <code>{codeData}</code>
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              </aside>
            )}
          </div>
      </div>
  );
}