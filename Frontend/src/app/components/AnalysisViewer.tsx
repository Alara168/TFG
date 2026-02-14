import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, AlertTriangle, Shield, Filter, Code } from 'lucide-react';

interface FunctionNode {
  id: string;
  name: string;
  attention: number;
  x: number;
  y: number;
  calls: string[];
}

const functionNodes: FunctionNode[] = [
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
  const [attentionFilter, setAttentionFilter] = useState(0);
  const [selectedFunction, setSelectedFunction] = useState<FunctionNode | null>(null);

  const filteredNodes = functionNodes.filter(node => node.attention >= attentionFilter);

  const getNodeColor = (attention: number) => {
    if (attention >= 0.8) return '#FF3131'; // Rojo para alta atención
    if (attention >= 0.5) return '#FFA500'; // Naranja para atención media
    return '#00FF41'; // Verde para benigno/baja atención
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Cabecera */}
      <header className="bg-card border-b border-border px-8 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => navigate('/dashboard')}
              className="text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div>
              <h1 className="text-xl font-bold text-foreground">Resultados del Análisis</h1>
              <p className="text-xs text-muted-foreground">malware_sample_1.exe</p>
            </div>
          </div>
          <button
            onClick={() => navigate('/dashboard')}
            className="text-sm text-primary hover:opacity-80 font-medium"
          >
            Volver al Historial
          </button>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        {/* Barra lateral izquierda - Clasificación */}
        <div className="w-80 bg-card border-r border-border p-6 space-y-6 overflow-y-auto">
          <div>
            <h2 className="text-lg font-semibold text-foreground mb-4">Clasificación</h2>
            <div className="bg-destructive/10 border border-destructive rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-6 h-6 text-destructive" />
                <span className="font-bold text-2xl text-destructive">98%</span>
              </div>
              <p className="text-destructive font-semibold">Malicioso</p>
              <p className="text-sm text-destructive/80 mt-1">Familia: Ransomware</p>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">Metadatos</h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <p className="text-muted-foreground">Tamaño</p>
                <p className="text-foreground font-mono">2.4 MB</p>
              </div>
              <div className="flex justify-between">
                <p className="text-muted-foreground">Arquitectura</p>
                <p className="text-foreground font-mono">x86_64</p>
              </div>
              <div className="flex justify-between">
                <p className="text-muted-foreground">Compilador</p>
                <p className="text-foreground font-mono">MSVC 19.0</p>
              </div>
              <div className="flex justify-between">
                <p className="text-muted-foreground">Entropía</p>
                <p className="text-foreground font-mono">7.89</p>
              </div>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">Indicadores de Amenaza</h3>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-destructive rounded-full"></div>
                <span className="text-foreground">Cifrado de Archivos</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-destructive rounded-full"></div>
                <span className="text-foreground">Comunicación C2</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-accent rounded-full"></div>
                <span className="text-foreground">Captura de Teclado (Keylogging)</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-destructive rounded-full"></div>
                <span className="text-foreground">Modificación del Registro</span>
              </div>
            </div>
          </div>
        </div>

        {/* Área Principal - Grafo de Llamadas */}
        <div className="flex-1 flex flex-col">
          {/* Barra Superior - Filtro de Atención */}
          <div className="bg-card border-b border-border px-6 py-4">
            <div className="flex items-center gap-4">
              <Filter className="w-5 h-5 text-muted-foreground" />
              <label className="text-sm text-foreground">Filtro de Atención (IA):</label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.1"
                value={attentionFilter}
                onChange={(e) => setAttentionFilter(parseFloat(e.target.value))}
                className="flex-1 max-w-xs accent-primary"
              />
              <span className="text-sm text-foreground font-mono bg-secondary px-2 py-1 rounded">
                {(attentionFilter * 100).toFixed(0)}%
              </span>
            </div>
          </div>

          {/* Grafo SVG */}
          <div className="flex-1 relative overflow-hidden bg-background">
            <svg className="w-full h-full">
              {/* Conexiones */}
              {filteredNodes.map(node =>
                node.calls.map(targetId => {
                  const target = filteredNodes.find(n => n.id === targetId);
                  if (!target) return null;
                  return (
                    <line
                      key={`${node.id}-${targetId}`}
                      x1={node.x}
                      y1={node.y + 15}
                      x2={target.x}
                      y2={target.y + 15}
                      stroke="#333"
                      strokeWidth="2"
                    />
                  );
                })
              )}

              {/* Nodos */}
              {filteredNodes.map(node => (
                <g key={node.id} onClick={() => setSelectedFunction(node)} className="cursor-pointer">
                  {node.attention >= 0.8 && (
                    <circle
                      cx={node.x}
                      cy={node.y + 15}
                      r="25"
                      fill={getNodeColor(node.attention)}
                      opacity="0.3"
                      className="animate-pulse"
                    />
                  )}
                  <circle
                    cx={node.x}
                    cy={node.y + 15}
                    r="18"
                    fill={getNodeColor(node.attention)}
                    stroke={selectedFunction?.id === node.id ? '#fff' : 'none'}
                    strokeWidth="3"
                  />
                  <text
                    x={node.x}
                    y={node.y + 50}
                    textAnchor="middle"
                    fill="#E0E0E0"
                    fontSize="12"
                    fontFamily="monospace"
                    className="font-medium"
                  >
                    {node.name}
                  </text>
                  <text
                    x={node.x}
                    y={node.y + 65}
                    textAnchor="middle"
                    fill="#888"
                    fontSize="10"
                    fontFamily="monospace"
                  >
                    {(node.attention * 100).toFixed(0)}%
                  </text>
                </g>
              ))}
            </svg>
          </div>
        </div>

        {/* Panel Derecho - Inspector de Código */}
        {selectedFunction && (
          <div className="w-96 bg-card border-l border-border p-6 overflow-y-auto shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                <Code className="w-5 h-5 text-primary" />
                Inspector de Código
              </h2>
              <button
                onClick={() => setSelectedFunction(null)}
                className="text-muted-foreground hover:text-foreground p-1"
              >
                ✕
              </button>
            </div>

            <div className="space-y-6">
              <div>
                <p className="text-sm text-muted-foreground mb-1">Función Detectada</p>
                <p className="text-foreground font-mono font-bold bg-secondary/50 px-2 py-1 rounded">
                  {selectedFunction.name}
                </p>
              </div>

              <div>
                <p className="text-sm text-muted-foreground mb-1">Peso de Atención (IA)</p>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 bg-secondary rounded-full overflow-hidden">
                    <div
                      className="h-full transition-all duration-500"
                      style={{
                        width: `${selectedFunction.attention * 100}%`,
                        backgroundColor: getNodeColor(selectedFunction.attention),
                      }}
                    ></div>
                  </div>
                  <span className="text-sm font-mono font-bold" style={{ color: getNodeColor(selectedFunction.attention) }}>
                    {(selectedFunction.attention * 100).toFixed(1)}%
                  </span>
                </div>
              </div>

              <div>
                <p className="text-sm text-muted-foreground mb-2">Código Descompilado (Pseudo-C)</p>
                <div className="bg-background border border-border rounded p-3 font-mono text-xs overflow-x-auto leading-relaxed">
                  <pre className="text-foreground">
                    <code>
{`void ${selectedFunction.name}() {
  // Código generado por el motor de IA
  ${selectedFunction.name === 'encrypt_files' ? `
  char* ruta = "C:\\\\Users\\\\";
  recorrer_directorio(ruta);
  for (archivo in archivos) {
    cifrado_aes(archivo);
    renombrar(archivo, ".locked");
  }` : selectedFunction.name === 'connect_c2' ? `
  char* servidor_c2 = "malicious.com";
  conectar(servidor_c2, 443);
  enviar_info_host();` : `
  // Implementación de la función
  ejecutar_accion_binaria();
  return 0;`}
}`}
                    </code>
                  </pre>
                </div>
              </div>

              {selectedFunction.name === 'encrypt_files' && (
                <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
                  <p className="text-sm text-muted-foreground mb-2">Coincidencias YARA</p>
                  <div className="bg-destructive/10 border border-destructive rounded p-3 text-xs">
                    <p className="text-destructive font-mono font-bold">ransomware_generico_v3</p>
                    <p className="text-destructive/80 mt-1">Detectado comportamiento de cifrado masivo de archivos.</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}