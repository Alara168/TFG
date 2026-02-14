import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, FileCode, Info, ArrowLeft, Play } from 'lucide-react';

export function UploadPage() {
  const navigate = useNavigate();
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [enableYARA, setEnableYARA] = useState(false);
  const [enablePseudoLabel, setEnablePseudoLabel] = useState(false);

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

  const handleAnalyze = () => {
    navigate('/analysis');
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  // Mock metadata
  const mockHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

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
            <div className="w-10 h-10 bg-primary/20 rounded-lg flex items-center justify-center">
              <FileCode className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground">Binary Upload</h1>
              <p className="text-xs text-muted-foreground">Deep Learning Analysis</p>
            </div>
          </div>
        </div>
      </header>

      <div className="p-8 max-w-4xl mx-auto space-y-8">
        {/* Drag & Drop Zone */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`
            border-2 border-dashed rounded-lg p-12 text-center transition-all
            ${isDragging ? 'border-primary bg-primary/10' : 'border-border bg-card'}
          `}
        >
          <input
            type="file"
            id="file-upload"
            className="hidden"
            onChange={handleFileSelect}
            accept=".exe,.dll,.bin,.elf,.so"
          />
          <label htmlFor="file-upload" className="cursor-pointer block">
            <Upload className={`w-16 h-16 mx-auto mb-4 ${isDragging ? 'text-primary' : 'text-muted-foreground'}`} />
            <h3 className="text-lg font-semibold text-foreground mb-2">
              {file ? file.name : 'Drag & Drop Binary File'}
            </h3>
            <p className="text-sm text-muted-foreground mb-4">
              {file ? 'Click to change file' : 'or click to browse'}
            </p>
            <p className="text-xs text-muted-foreground">
              Supported formats: .exe, .dll, .bin, .elf, .so
            </p>
          </label>
        </div>

        {/* Metadata Preview */}
        {file && (
          <div className="bg-card border border-border rounded-lg p-6 space-y-4">
            <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <Info className="w-5 h-5 text-primary" />
              Metadata Preview
            </h2>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-muted-foreground mb-1">File Size</p>
                <p className="text-foreground font-mono">{formatFileSize(file.size)}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-1">Architecture</p>
                <p className="text-foreground font-mono">x86_64</p>
              </div>
              <div className="col-span-2">
                <p className="text-sm text-muted-foreground mb-1">SHA-256 Hash</p>
                <p className="text-foreground font-mono text-xs break-all">{mockHash}</p>
              </div>
            </div>
          </div>
        )}

        {/* Advanced Options */}
        <div className="bg-card border border-border rounded-lg p-6 space-y-4">
          <h2 className="text-lg font-semibold text-foreground">Advanced Options</h2>
          
          <div className="flex items-center justify-between py-3 border-b border-border">
            <div>
              <p className="text-foreground">YARA Scanning</p>
              <p className="text-xs text-muted-foreground">Apply signature-based detection rules</p>
            </div>
            <label className="relative inline-block w-12 h-6">
              <input
                type="checkbox"
                checked={enableYARA}
                onChange={(e) => setEnableYARA(e.target.checked)}
                className="sr-only peer"
              />
              <span className="absolute inset-0 bg-secondary rounded-full transition-colors peer-checked:bg-primary cursor-pointer"></span>
              <span className="absolute left-1 top-1 w-4 h-4 bg-white rounded-full transition-transform peer-checked:translate-x-6"></span>
            </label>
          </div>

          <div className="flex items-center justify-between py-3">
            <div>
              <p className="text-foreground">Pseudo-labeling</p>
              <p className="text-xs text-muted-foreground">Enable semi-supervised learning mode</p>
            </div>
            <label className="relative inline-block w-12 h-6">
              <input
                type="checkbox"
                checked={enablePseudoLabel}
                onChange={(e) => setEnablePseudoLabel(e.target.checked)}
                className="sr-only peer"
              />
              <span className="absolute inset-0 bg-secondary rounded-full transition-colors peer-checked:bg-primary cursor-pointer"></span>
              <span className="absolute left-1 top-1 w-4 h-4 bg-white rounded-full transition-transform peer-checked:translate-x-6"></span>
            </label>
          </div>
        </div>

        {/* Analyze Button */}
        {file && (
          <button
            onClick={handleAnalyze}
            className="w-full bg-primary text-primary-foreground py-4 rounded-lg hover:opacity-90 transition-opacity flex items-center justify-center gap-2 font-semibold text-lg"
          >
            <Play className="w-5 h-5" />
            Start Deep Analysis
          </button>
        )}
      </div>
    </div>
  );
}
