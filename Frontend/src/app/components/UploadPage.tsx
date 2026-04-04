import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, FileCode, Info, ArrowLeft, Play, Loader2, LogOut, CheckCircle2 } from 'lucide-react';
import { apiClient } from '../services/api.client';
import { authService } from '../services/auth.service';

// Pasos de la simulación técnica
const ANALYSIS_STEPS = [
  "Cargando binario en el entorno seguro...",
  "Calculando hashes SHA-256 y MD5...",
  "Extrayendo secciones del ejecutable (PE/ELF)...",
  "Desensamblando funciones críticas...",
  "Ejecutando motor de inferencia Deep Learning...",
  "Generando grafo de dependencias y atención...",
  "Finalizando reporte de seguridad..."
];

export function UploadPage() {
  const navigate = useNavigate();
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [enablePseudoLabel, setEnablePseudoLabel] = useState(false);
  
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const MAX_SIZE = 10 * 1024 * 1024; // 10MB

  // Función para forzar la espera
  const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

  const handleAnalyze = async () => {
    if (!file) return;

    // Comprobación de tamaño
    if (file.size > MAX_SIZE) {
      setError(`Error: El archivo supera el límite de 10MB (Peso: ${formatFileSize(file.size)}).`);
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setCurrentStep(0);

    const formData = new FormData();
    formData.append('archivo', file);
    formData.append('enable_pseudo_label', String(enablePseudoLabel));

    try {
      const apiPromise = apiClient('/analizar/', {
        method: 'POST',
        body: formData,
      });

      const stepDuration = 5000 / ANALYSIS_STEPS.length;
      
      for (let i = 0; i < ANALYSIS_STEPS.length; i++) {
        setCurrentStep(i);
        await delay(stepDuration);
      }

      const response = await apiPromise;

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Error desconocido' }));
        throw new Error(errorData.detail || 'Error en el servidor');
      }

      const analysisData = await response.json();
      await delay(500);
      navigate(`/analisis/${analysisData.id}`, { state: { result: analysisData } });
      
    } catch (err: any) {
      if (err !== 'Unauthorized') {
        setError(err.message);
      }
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
    <div className="min-h-screen bg-background text-foreground font-sans">
      <header className="bg-card border-b border-border px-8 py-4">
        <div className="flex items-center justify-between">
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
                <p className="text-xs text-muted-foreground uppercase tracking-widest font-semibold">Inferencia de Redes Neuronales</p>
              </div>
            </div>
          </div>
          <button
            onClick={() => authService.logout()}
            className="bg-secondary text-secondary-foreground px-4 py-2 rounded-md hover:bg-secondary/50 transition-all flex items-center gap-2 border border-border text-sm font-bold"
          >
            <LogOut className="w-4 h-4" />
            Cerrar Sesión
          </button>
        </div>
      </header>

      <div className="p-8 max-w-4xl mx-auto space-y-8">
        
        {/* ÁREA DE CARGA O PROCESO */}
        {!isAnalyzing ? (
          <div
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setIsDragging(false);
              if (e.dataTransfer.files?.[0]) {
                setFile(e.dataTransfer.files[0]);
                setError(null); // Limpiar error al soltar nuevo archivo
              }
            }}
            className={`
              border-2 border-dashed rounded-xl p-16 text-center transition-all duration-300
              ${isDragging ? 'border-primary bg-primary/5 scale-[1.01]' : 'border-border bg-card'}
            `}
          >
            <input
              type="file"
              id="file-upload"
              className="hidden"
              onChange={(e) => {
                if (e.target.files?.[0]) {
                  setFile(e.target.files[0]);
                  setError(null);
                }
              }}
              accept=".exe,.dll,.bin,.elf,.so"
            />
            <label htmlFor="file-upload" className="cursor-pointer block">
              <Upload className={`w-20 h-20 mx-auto mb-6 transition-colors ${isDragging ? 'text-primary' : 'text-muted-foreground/40'}`} />
              <h3 className="text-xl font-bold mb-2">
                {file ? file.name : 'Arrastre su binario aquí'}
              </h3>
              <p className="text-sm text-muted-foreground">
                Soporte para formatos PE (Windows) y ELF (Linux/Unix)
              </p>
            </label>
          </div>
        ) : (
          <div className="bg-card border border-primary/20 rounded-xl p-12 shadow-2xl shadow-primary/5 animate-in fade-in zoom-in-95 duration-500">
            <div className="flex flex-col items-center text-center">
              <div className="relative mb-8">
                <Loader2 className="w-24 h-24 text-primary animate-spin" />
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="w-12 h-12 bg-primary/10 rounded-full animate-ping" />
                </div>
              </div>
              <h2 className="text-2xl font-black uppercase tracking-tighter mb-8 text-primary">Procesando Inteligencia...</h2>
              <div className="w-full max-w-md space-y-3">
                {ANALYSIS_STEPS.map((step, index) => (
                  <div key={index} className={`flex items-center gap-3 transition-all duration-500 ${index === currentStep ? 'text-primary scale-105 font-bold' : index < currentStep ? 'text-emerald-500 opacity-60' : 'text-muted-foreground opacity-20'}`}>
                    {index < currentStep ? <CheckCircle2 className="w-5 h-5 shrink-0" /> : <div className={`w-5 h-5 rounded-full border-2 shrink-0 ${index === currentStep ? 'border-primary animate-pulse' : 'border-current'}`} />}
                    <span className="text-sm font-mono tracking-tight">{step}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {file && !isAnalyzing && (
          <>
            <div className={`bg-card border rounded-xl p-6 space-y-4 shadow-sm transition-colors ${file.size > MAX_SIZE ? 'border-destructive/50 shadow-destructive/10' : 'border-border'}`}>
              <h2 className="text-sm font-black uppercase tracking-widest text-primary/60 flex items-center gap-2">
                <Info className="w-4 h-4" />
                Metadatos Iniciales
              </h2>
              <div className="grid grid-cols-2 gap-8">
                <div className="bg-background/50 p-3 rounded-lg border border-border/50">
                  <p className="text-[10px] uppercase font-bold text-muted-foreground mb-1">Tamaño (Máx. 10MB)</p>
                  <p className={`font-mono text-lg ${file.size > MAX_SIZE ? 'text-destructive font-bold' : ''}`}>{formatFileSize(file.size)}</p>
                </div>
                <div className="bg-background/50 p-3 rounded-lg border border-border/50">
                  <p className="text-[10px] uppercase font-bold text-muted-foreground mb-1">Arquitectura Estimada</p>
                  <p className="font-mono text-lg">x86_64 / Multi-Section</p>
                </div>
              </div>
            </div>

            {/* ERROR UBICADO AQUÍ PARA VISIBILIDAD INMEDIATA */}
            {error && (
              <div className="bg-destructive/10 border border-destructive/20 text-destructive p-4 rounded-xl text-sm flex items-center gap-3 animate-in slide-in-from-top-2">
                <AlertTriangle className="w-5 h-5 shrink-0" />
                <span className="font-bold">{error}</span>
              </div>
            )}

            <div className="bg-card border border-border rounded-xl p-6 space-y-4">
              <h2 className="text-sm font-black uppercase tracking-widest text-primary/60">Configuración del Motor</h2>
              <div className="space-y-2">
                
                <button 
                  onClick={() => setEnablePseudoLabel(!enablePseudoLabel)}
                  className={`w-full flex items-center justify-between p-4 rounded-xl border transition-all ${enablePseudoLabel ? 'bg-primary/5 border-primary text-primary' : 'bg-background border-border text-muted-foreground'}`}
                >
                  <div className="text-left">
                    <p className="font-bold text-sm">Pseudo-etiquetado Automático</p>
                    <p className="text-[10px] opacity-70">Mejora de confianza mediante aprendizaje semi-supervisado</p>
                  </div>
                  <div className={`w-10 h-5 rounded-full relative transition-colors ${enablePseudoLabel ? 'bg-primary' : 'bg-muted'}`}>
                    <div className={`absolute top-1 w-3 h-3 bg-white rounded-full transition-all ${enablePseudoLabel ? 'left-6' : 'left-1'}`} />
                  </div>
                </button>
              </div>
            </div>

            <button
              onClick={handleAnalyze}
              disabled={file.size > MAX_SIZE}
              className={`w-full py-5 rounded-xl transition-all flex items-center justify-center gap-3 font-black uppercase tracking-tighter text-xl shadow-lg 
                ${file.size > MAX_SIZE 
                  ? 'bg-muted text-muted-foreground cursor-not-allowed opacity-50' 
                  : 'bg-primary text-primary-foreground hover:brightness-110 shadow-primary/20'}`}
            >
              <Play className="w-6 h-6 fill-current" />
              {file.size > MAX_SIZE ? 'Archivo demasiado grande' : 'Iniciar Análisis Profundo'}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

function AlertTriangle(props: any) {
  return (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
  );
}