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
    if (attention >= 0.8) return '#FF3131';
    if (attention >= 0.5) return '#FFA500';
    return '#00FF41';
  };

  return (
    <div className="min-h-screen bg-background flex flex-col">
      {/* Header */}
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
              <h1 className="text-xl font-bold text-foreground">Analysis Results</h1>
              <p className="text-xs text-muted-foreground">malware_sample_1.exe</p>
            </div>
          </div>
          <button
            onClick={() => navigate('/dashboard')}
            className="text-sm text-primary hover:opacity-80"
          >
            Back to History
          </button>
        </div>
      </header>

      <div className="flex-1 flex">
        {/* Left Sidebar - Classification Result */}
        <div className="w-80 bg-card border-r border-border p-6 space-y-6 overflow-y-auto">
          <div>
            <h2 className="text-lg font-semibold text-foreground mb-4">Classification</h2>
            <div className="bg-destructive/10 border border-destructive rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-6 h-6 text-destructive" />
                <span className="font-bold text-2xl text-destructive">98%</span>
              </div>
              <p className="text-destructive font-semibold">Malicious</p>
              <p className="text-sm text-destructive/80 mt-1">Ransomware Family</p>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">Metadata</h3>
            <div className="space-y-2 text-sm">
              <div>
                <p className="text-muted-foreground">File Size</p>
                <p className="text-foreground font-mono">2.4 MB</p>
              </div>
              <div>
                <p className="text-muted-foreground">Architecture</p>
                <p className="text-foreground font-mono">x86_64</p>
              </div>
              <div>
                <p className="text-muted-foreground">Compiler</p>
                <p className="text-foreground font-mono">MSVC 19.0</p>
              </div>
              <div>
                <p className="text-muted-foreground">Entropy</p>
                <p className="text-foreground font-mono">7.89</p>
              </div>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground mb-3">Threat Indicators</h3>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-destructive rounded-full"></div>
                <span className="text-foreground">File Encryption</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-destructive rounded-full"></div>
                <span className="text-foreground">C2 Communication</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-accent rounded-full"></div>
                <span className="text-foreground">Keylogging</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <div className="w-2 h-2 bg-destructive rounded-full"></div>
                <span className="text-foreground">Registry Modification</span>
              </div>
            </div>
          </div>
        </div>

        {/* Main Area - Call Graph */}
        <div className="flex-1 flex flex-col">
          {/* Top Bar - Attention Filter */}
          <div className="bg-card border-b border-border px-6 py-4">
            <div className="flex items-center gap-4">
              <Filter className="w-5 h-5 text-muted-foreground" />
              <label className="text-sm text-foreground">Attention Filter:</label>
              <input
                type="range"
                min="0"
                max="1"
                step="0.1"
                value={attentionFilter}
                onChange={(e) => setAttentionFilter(parseFloat(e.target.value))}
                className="flex-1 max-w-xs"
              />
              <span className="text-sm text-foreground font-mono">{attentionFilter.toFixed(1)}</span>
            </div>
          </div>

          {/* Call Graph */}
          <div className="flex-1 relative overflow-hidden bg-background">
            <svg className="w-full h-full">
              {/* Draw connections */}
              {filteredNodes.map(node =>
                node.calls.map(targetId => {
                  const target = filteredNodes.find(n => n.id === targetId);
                  if (!target) return null;
                  return (
                    <line
                      key={`${node.id}-${targetId}`}
                      x1={node.x}
                      y1={node.y + 30}
                      x2={target.x}
                      y2={target.y}
                      stroke="#333"
                      strokeWidth="2"
                    />
                  );
                })
              )}

              {/* Draw nodes */}
              {filteredNodes.map(node => (
                <g key={node.id} onClick={() => setSelectedFunction(node)} className="cursor-pointer">
                  {/* Glow effect for high attention */}
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
                  {/* Node circle */}
                  <circle
                    cx={node.x}
                    cy={node.y + 15}
                    r="18"
                    fill={getNodeColor(node.attention)}
                    stroke={selectedFunction?.id === node.id ? '#fff' : 'none'}
                    strokeWidth="3"
                  />
                  {/* Node label */}
                  <text
                    x={node.x}
                    y={node.y + 50}
                    textAnchor="middle"
                    fill="#E0E0E0"
                    fontSize="12"
                    fontFamily="monospace"
                  >
                    {node.name}
                  </text>
                  {/* Attention score */}
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

        {/* Right Side Panel - Code Inspector */}
        {selectedFunction && (
          <div className="w-96 bg-card border-l border-border p-6 overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                <Code className="w-5 h-5 text-primary" />
                Code Inspector
              </h2>
              <button
                onClick={() => setSelectedFunction(null)}
                className="text-muted-foreground hover:text-foreground"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-1">Function</p>
                <p className="text-foreground font-mono font-semibold">{selectedFunction.name}</p>
              </div>

              <div>
                <p className="text-sm text-muted-foreground mb-1">Attention Weight</p>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-2 bg-secondary rounded-full overflow-hidden">
                    <div
                      className="h-full"
                      style={{
                        width: `${selectedFunction.attention * 100}%`,
                        backgroundColor: getNodeColor(selectedFunction.attention),
                      }}
                    ></div>
                  </div>
                  <span className="text-sm font-mono" style={{ color: getNodeColor(selectedFunction.attention) }}>
                    {(selectedFunction.attention * 100).toFixed(1)}%
                  </span>
                </div>
              </div>

              <div>
                <p className="text-sm text-muted-foreground mb-2">Pseudo-C Code</p>
                <div className="bg-background border border-border rounded p-3 font-mono text-xs overflow-x-auto">
                  <pre className="text-foreground">
                    <code>
{`void ${selectedFunction.name}() {
  // Decompiled code
  ${selectedFunction.name === 'encrypt_files' ? `
  char* path = "C:\\\\Users\\\\";
  traverse_dir(path);
  for (file in files) {
    aes_encrypt(file);
    rename(file, ".locked");
  }` : selectedFunction.name === 'connect_c2' ? `
  char* c2_server = "malicious.com";
  connect(c2_server, 443);
  send_host_info();` : `
  // Function implementation
  perform_action();
  return 0;`}
}`}
                    </code>
                  </pre>
                </div>
              </div>

              {selectedFunction.name === 'encrypt_files' && (
                <div>
                  <p className="text-sm text-muted-foreground mb-2">YARA Matches</p>
                  <div className="bg-destructive/10 border border-destructive rounded p-3 text-xs">
                    <p className="text-destructive font-mono">ransomware_generic</p>
                    <p className="text-destructive/80 mt-1">File encryption behavior detected</p>
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
