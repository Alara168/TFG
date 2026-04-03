import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom'; // 1. Importar navigate
import { Search, ArrowUpDown, Database, FileText, Loader2, ArrowLeft } from 'lucide-react'; // 2. Importar ArrowLeft
import { apiClient } from '../services/api.client';

export function DatasetExplorer() {
  const navigate = useNavigate(); // 3. Inicializar navigate
  const [dataset, setDataset] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [sortConfig, setSortConfig] = useState({ key: 'atencion_score', direction: 'desc' });

  const [filters, setFilters] = useState({
    fichero: '',
    direccion: '',
    score: '',
    instrucciones: '',
    entropia: '',
    complejidad: '',
    clase: ''
  });

  const fetchFilteredData = useCallback(async () => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams(filters).toString();
      const res = await apiClient(`/admin/full-dataset-explorer/?${params}`);
      const data = await res.json();
      
      const flattened = data.flatMap((analisis: any) => 
        analisis.detalles_funciones.map((func: any) => ({
          ...func,
          nombre_fichero: analisis.nombre_fichero,
          resultado_clase: analisis.resultado_clase,
          hash_sha256: analisis.hash_sha256
        }))
      );
      setDataset(flattened);
    } catch (err) {
      console.error("Error cargando el dataset:", err);
    } finally {
      setIsLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchFilteredData();
    }, 500);
    return () => clearTimeout(timer);
  }, [fetchFilteredData]);

  const handleFilterChange = (column: string, value: string) => {
    setFilters(prev => ({ ...prev, [column]: value }));
  };

  const handleSort = (key: string) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'desc' ? 'asc' : 'desc'
    }));
  };

  const sortedData = [...dataset].sort((a: any, b: any) => {
    if (a[sortConfig.key] < b[sortConfig.key]) return sortConfig.direction === 'asc' ? -1 : 1;
    if (a[sortConfig.key] > b[sortConfig.key]) return sortConfig.direction === 'asc' ? 1 : -1;
    return 0;
  });

  return (
    <div className="bg-card border-none min-h-screen w-full shadow-xl overflow-hidden rounded-none">
      
      {/* TOOLBAR SUPERIOR ACTUALIZADO */}
      <div className="p-4 border-b border-border bg-secondary/10 flex items-center justify-between">
        <div className="flex items-center gap-4">
          {/* BOTÓN VOLVER ATRÁS */}
          <button
            onClick={() => navigate('/admin')}
            className="p-2 text-muted-foreground hover:text-primary hover:bg-primary/10 rounded-full transition-all"
            title="Volver al Panel de Administración"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>

          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary/10 rounded-lg">
              <Database className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-foreground">Dataset Explorer</h2>
              <p className="text-[10px] text-muted-foreground uppercase tracking-tight">Búsqueda avanzada en tiempo real</p>
            </div>
          </div>
        </div>
        {isLoading && <Loader2 className="w-4 h-4 animate-spin text-primary" />}
      </div>

      {/* TABLA CON BUSCADORES POR COLUMNA */}
      <div className="overflow-x-auto h-[calc(100vh-73px)] custom-scrollbar">
        <table className="w-full border-separate border-spacing-0 text-left">
          <thead className="sticky top-0 z-20 bg-[#1A1A1A]">
            <tr>
              <SortHeader label="Archivo" skey="nombre_fichero" conf={sortConfig} onSort={handleSort} />
              <SortHeader label="Función (Addr)" skey="direccion_memoria" conf={sortConfig} onSort={handleSort} />
              <SortHeader label="Score Atención" skey="atencion_score" conf={sortConfig} onSort={handleSort} />
              <SortHeader label="Instrucciones" skey="num_instrucciones" conf={sortConfig} onSort={handleSort} />
              <SortHeader label="Entropía" skey="entropia" conf={sortConfig} onSort={handleSort} />
              <SortHeader label="Complejidad (CC)" skey="complejidad" conf={sortConfig} onSort={handleSort} />
              <SortHeader label="Predicción" skey="resultado_clase" conf={sortConfig} onSort={handleSort} />
            </tr>
            <tr className="bg-[#1A1A1A] border-b border-border">
              <FilterCell value={filters.fichero} onChange={(v: string) => handleFilterChange('fichero', v)} placeholder="Buscar Archivo" />
              <FilterCell value={filters.direccion} onChange={(v: string) => handleFilterChange('direccion', v)} placeholder="Dirección Memoria" mono />
              <FilterCell value={filters.score} onChange={(v: string) => handleFilterChange('score', v)} placeholder="Mín. Score" />
              <FilterCell value={filters.instrucciones} onChange={(v: string) => handleFilterChange('instrucciones', v)} placeholder="Mín. Instrucciones" />
              <FilterCell value={filters.entropia} onChange={(v: string) => handleFilterChange('entropia', v)} placeholder="Mín. Entropía" />
              <FilterCell value={filters.complejidad} onChange={(v: string) => handleFilterChange('complejidad', v)} placeholder="Mín. Complejidad" />
              <th className="p-2 border-b border-border">
                <select 
                  className="w-full bg-background border border-border rounded px-2 py-1 text-[10px] outline-none focus:ring-1 focus:ring-primary text-foreground"
                  value={filters.clase}
                  onChange={(e) => handleFilterChange('clase', e.target.value)}
                >
                  <option value="">Todas</option>
                  <option value="Benigno">Benigno</option>
                  <option value="Intrusion">Intrusion</option>
                  <option value="Financiero">Financiero</option>
                  <option value="Herramientas/Sistema">Herramientas/Sistema</option>
                  <option value="Otros/Ransom">Otros/Ransom</option>
                </select>
              </th>
            </tr>
          </thead>
          
          <tbody className="divide-y divide-border/40">
            {sortedData.map((row, i) => (
              <tr key={i} className="hover:bg-primary/5 transition-colors group">
                <td className="p-3 text-xs border-r border-border/10">
                  <div className="flex items-center gap-2">
                    <FileText className="w-3 h-3 text-muted-foreground" />
                    <span className="font-medium text-foreground truncate max-w-[120px]">{row.nombre_fichero}</span>
                  </div>
                </td>
                <td className="p-3 text-[11px] font-mono text-blue-400 border-r border-border/10">
                  {row.direccion_memoria}
                </td>
                <td className="p-3 border-r border-border/10">
                  <div className="flex items-center gap-2">
                    <div className="w-12 h-1 bg-secondary rounded-full overflow-hidden hidden sm:block">
                      <div className="h-full bg-primary" style={{ width: `${row.atencion_score * 100}%` }} />
                    </div>
                    <span className="text-[10px] font-mono text-foreground">{(row.atencion_score).toFixed(4)}</span>
                  </div>
                </td>
                <td className="p-3 text-xs text-muted-foreground border-r border-border/10">{row.num_instrucciones}</td>
                <td className="p-3 text-xs text-muted-foreground border-r border-border/10">{row.entropia.toFixed(2)}</td>
                <td className="p-3 text-xs text-center font-bold text-accent border-r border-border/10">{row.complejidad}</td>
                <td className="p-3">
                  <span className={`text-[9px] font-bold px-2 py-0.5 rounded border ${
                    row.resultado_clase === 'Benigno' 
                    ? 'border-primary/30 text-primary bg-primary/5' 
                    : 'border-destructive/30 text-destructive bg-destructive/5'
                  }`}>
                    {row.resultado_clase}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function SortHeader({ label, skey, conf, onSort }: any) {
  return (
    <th 
      className="p-3 text-[10px] uppercase tracking-wider font-bold text-muted-foreground border-b border-border cursor-pointer hover:bg-secondary/20 transition-all"
      onClick={() => onSort(skey)}
    >
      <div className="flex items-center gap-1.5">
        {label}
        <ArrowUpDown className={`w-3 h-3 ${conf.key === skey ? 'text-primary' : 'opacity-20'}`} />
      </div>
    </th>
  );
}

function FilterCell({ value, onChange, placeholder, mono = false }: any) {
  return (
    <th className="p-2 border-b border-border">
      <input 
        className={`w-full bg-background border border-border rounded px-2 py-1 text-[10px] outline-none focus:ring-1 focus:ring-primary text-foreground placeholder:text-muted-foreground/50 ${mono ? 'font-mono' : ''}`}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </th>
  );
}