import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, FileCode, Info, ArrowLeft, Play, Loader2, LogOut } from 'lucide-react';
import { apiClient } from '../services/api.client'; // Importamos el cliente
import { authService } from '../services/auth.service';

export function UploadPage() {
  const navigate = useNavigate();
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [enableYARA, setEnableYARA] = useState(false);
  const [enablePseudoLabel, setEnablePseudoLabel] = useState(false);
  
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };


  const handleDragLeave = () => {
    setIsDragging(false);
  };


  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  };


  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleAnalyze = async () => {
    if (!file) return;

    setIsAnalyzing(true);
    setError(null);

    const formData = new FormData();
    formData.append('archivo', file);
    formData.append('enable_yara', String(enableYARA));
    formData.append('enable_pseudo_label', String(enablePseudoLabel));

    try {
      // Usamos apiClient con POST y el cuerpo FormData
      const response = await apiClient('/analizar/', {
        method: 'POST',
        body: formData,
        // IMPORTANTE: Aquí NO pasamos headers, el cliente ya pone el token
      });

      if (!response.ok) {
        // Intentamos parsear el error del backend
        const errorData = await response.json().catch(() => ({ detail: 'Error desconocido' }));
        throw new Error(errorData.detail || 'Error en el servidor');
      }

      const analysisData = await response.json();
      navigate(`/analisis/${analysisData.id}`, { state: { result: analysisData } });
      
    } catch (err: any) {
      if (err !== 'Unauthorized') { // Evitamos mostrar error si fue una redirección 401
        setError(err.message);
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="bg-card border-b border-border px-8 py-4">
        <div className="flex items-center justify-between">
          {/* Contenedor Izquierdo: Retroceso + Logo/Título */}
          <div className="flex items-center gap-6">
            <button
              onClick={() => navigate('/dashboard')}
              className="text-muted-foreground hover:text-foreground transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-primary/20 rounded-lg flex items-center justify-center">
                <FileCode className="w-6 h-6 text-primary" />
              </div>
              <div>
                <h1 className="text-xl font-bold">Subida de Binarios</h1>
                <p className="text-xs text-muted-foreground">Análisis mediante Deep Learning</p>
              </div>
            </div>
          </div>

          {/* Contenedor Derecho: Botón Salir */}
          <button
            onClick={() => authService.logout()}
            className="bg-secondary text-secondary-foreground px-4 py-2 rounded-md hover:bg-secondary/50 transition-all flex items-center gap-2 border border-border"
          >
            <LogOut className="w-4 h-4" />
            Salir
          </button>
        </div>
      </header>

      <div className="p-8 max-w-4xl mx-auto space-y-8">
        {error && (
          <div className="bg-destructive/10 border border-destructive/20 text-destructive p-4 rounded-lg text-sm">
            {error}
          </div>
        )}

        <div
          onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setIsDragging(false);
            if (e.dataTransfer.files?.[0]) setFile(e.dataTransfer.files[0]);
          }}
          className={`
            border-2 border-dashed rounded-lg p-12 text-center transition-all
            ${isDragging ? 'border-primary bg-primary/10' : 'border-border bg-card'}
          `}
        >
          <input
            type="file"
            id="file-upload"
            className="hidden"
            onChange={(e) => e.target.files?.[0] && setFile(e.target.files[0])}
            accept=".exe,.dll,.bin,.elf,.so"
            disabled={isAnalyzing}
          />
          <label htmlFor="file-upload" className={`cursor-pointer block ${isAnalyzing && 'opacity-50 cursor-not-allowed'}`}>
            <Upload className={`w-16 h-16 mx-auto mb-4 ${isDragging ? 'text-primary' : 'text-muted-foreground'}`} />
            <h3 className="text-lg font-semibold mb-2">
              {file ? file.name : 'Arrastre y suelte el archivo binario'}
            </h3>
            <p className="text-sm text-muted-foreground mb-4">
              {file ? 'Haga clic para cambiar de archivo' : 'o haga clic para buscar en su equipo'}
            </p>
          </label>
        </div>

        {file && (
          <div className="bg-card border border-border rounded-lg p-6 space-y-4 shadow-sm">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Info className="w-5 h-5 text-primary" />
              Vista Previa de Metadatos
            </h2>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-muted-foreground mb-1">Tamaño del Archivo</p>
                <p className="font-mono">{formatFileSize(file.size)}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-1">Arquitectura Detectada</p>
                <p className="font-mono">x86_64 / PE</p>
              </div>
            </div>
          </div>
        )}

        {/* Opciones Avanzadas (YARA y Pseudo-label) */}
        <div className="bg-card border border-border rounded-lg p-6 space-y-4">
          <h2 className="text-lg font-semibold">Opciones Avanzadas</h2>
          <div className="flex items-center justify-between py-3 border-b border-border">
            <div>
              <p className="font-medium">Escaneo YARA</p>
              <p className="text-xs text-muted-foreground">Aplicar reglas de detección basadas en firmas</p>
            </div>
            <label className="relative inline-block w-12 h-6">
              <input
                type="checkbox"
                checked={enableYARA}
                onChange={(e) => setEnableYARA(e.target.checked)}
                className="sr-only peer"
                disabled={isAnalyzing}
              />
              <span className="absolute inset-0 bg-secondary rounded-full transition-colors peer-checked:bg-primary cursor-pointer"></span>
              <span className="absolute left-1 top-1 w-4 h-4 bg-white rounded-full transition-transform peer-checked:translate-x-6"></span>
            </label>
          </div>
          <div className="flex items-center justify-between py-3">
            <div>
              <p className="font-medium">Pseudo-etiquetado</p>
              <p className="text-xs text-muted-foreground">Activar modo de aprendizaje semi-supervisado</p>
            </div>
            <label className="relative inline-block w-12 h-6">
              <input
                type="checkbox"
                checked={enablePseudoLabel}
                onChange={(e) => setEnablePseudoLabel(e.target.checked)}
                className="sr-only peer"
                disabled={isAnalyzing}
              />
              <span className="absolute inset-0 bg-secondary rounded-full transition-colors peer-checked:bg-primary cursor-pointer"></span>
              <span className="absolute left-1 top-1 w-4 h-4 bg-white rounded-full transition-transform peer-checked:translate-x-6"></span>
            </label>
          </div>
        </div>

        {file && (
          <button
            onClick={handleAnalyze}
            disabled={isAnalyzing}
            className="w-full bg-primary text-primary-foreground py-4 rounded-lg hover:opacity-90 transition-all flex items-center justify-center gap-2 font-semibold text-lg disabled:opacity-50"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                Analizando Binario...
              </>
            ) : (
              <>
                <Play className="w-5 h-5" />
                Iniciar Análisis Profundo
              </>
            )}
          </button>
        )}
      </div>
    </div>
  );
}