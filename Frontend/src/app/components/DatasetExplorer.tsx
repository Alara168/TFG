import React, { useEffect, useState } from 'react';
import { Search, ArrowUpDown, Database, FileText, Loader2, Filter } from 'lucide-react';
import { apiClient } from '../services/api.client';

export function DatasetExplorer() {
  const [dataset, setDataset] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [sortConfig, setSortConfig] = useState({ key: 'atencion_score', direction: 'desc' });

  // 1. LLAMADA AL BACKEND
  useEffect(() => {
    const loadDataset = async () => {
      setIsLoading(true);
      try {
        // Cambia esta URL por tu endpoint real de Django
        const res = await apiClient('/admin/full-dataset-explorer/');
        const data = await res.json();
        
        // Aplanamos la relación Analisis -> 20 Funciones
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
    };
    loadDataset();
  }, []);

  // 2. LÓGICA DE FILTRADO Y ORDENACIÓN (Local para velocidad tipo Excel)
  const filteredData = dataset.filter(item => 
    item.nombre_fichero.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.direccion_memoria.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const sortedData = [...filteredData].sort((a: any, b: any) => {
    if (a[sortConfig.key] < b[sortConfig.key]) return sortConfig.direction === 'asc' ? -1 : 1;
    if (a[sortConfig.key] > b[sortConfig.key]) return sortConfig.direction === 'asc' ? 1 : -1;
    return 0;
  }).slice(0, 50);

  const handleSort = (key: string) => {
    setSortConfig(prev => ({
      key,
      direction: prev.key === key && prev.direction === 'desc' ? 'asc' : 'desc'
    }));
  };

  if (isLoading) {
    return (
      <div className="h-64 flex flex-col items-center justify-center bg-card border border-border rounded-lg">
        <Loader2 className="w-8 h-8 animate-spin text-primary mb-2" />
        <p className="text-sm text-muted-foreground">Explorando base de datos...</p>
      </div>
    );
  }

  return (
    <div className="bg-card border border-border rounded-lg shadow-xl overflow-hidden">
      {/* TOOLBAR SUPERIOR */}
      <div className="p-4 border-b border-border bg-secondary/10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <Database className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-foreground">Dataset Explorer</h2>
            <p className="text-[10px] text-muted-foreground uppercase tracking-tight">Muestra de 50 registros MIL</p>
          </div>
        </div>

        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Buscar en el dataset..."
            className="bg-background border border-border rounded-md py-1.5 pl-9 pr-4 text-xs w-64 focus:ring-1 focus:ring-primary outline-none transition-all"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      {/* TABLA ESTILO HOJA DE CÁLCULO */}
      <div className="overflow-x-auto max-h-[500px] custom-scrollbar">
        <table className="w-full border-separate border-spacing-0 text-left">
          <thead className="sticky top-0 z-20 bg-[#1A1A1A]">
            <tr>
              <SortHeader label="Archivo" skey="nombre_fichero" conf={sortConfig} onSort={handleSort} />
              <SortHeader label="Función (Addr)" skey="direccion_memoria" conf={sortConfig} onSort={handleSort} />
              <SortHeader label="Score Atención" skey="atencion_score" conf={sortConfig} onSort={handleSort} />
              <SortHeader label="Instrucciones" skey="num_instrucciones" conf={sortConfig} onSort={handleSort} />
              <SortHeader label="Entropía" skey="entropia" conf={sortConfig} onSort={handleSort} />
              <SortHeader label="Predicción" skey="resultado_clase" conf={sortConfig} onSort={handleSort} />
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
                    <div className="w-16 h-1 bg-secondary rounded-full overflow-hidden">
                      <div className="h-full bg-primary" style={{ width: `${row.atencion_score * 100}%` }} />
                    </div>
                    <span className="text-[10px] font-mono text-foreground">{(row.atencion_score).toFixed(4)}</span>
                  </div>
                </td>
                <td className="p-3 text-xs text-muted-foreground border-r border-border/10">{row.num_instrucciones}</td>
                <td className="p-3 text-xs text-muted-foreground border-r border-border/10">{row.entropia.toFixed(2)}</td>
                <td className="p-3">
                  <span className={`text-[9px] font-bold px-2 py-0.5 rounded uppercase border ${
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
      
      {/* FOOTER */}
      <div className="p-2 bg-secondary/5 border-t border-border flex justify-between items-center text-[10px] text-muted-foreground">
        <span>Mostrando {sortedData.length} de {filteredData.length} resultados filtrados</span>
        <span>Relación 1:20 (Fichero:Funciones)</span>
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