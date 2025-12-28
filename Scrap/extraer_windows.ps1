# 1. Configuración
$destino = "C:\DatasetTFG"
if (!(Test-Path $destino)) { New-Item -ItemType Directory -Path $destino }

$contador = 0
$maximo = 20000

# 2. Definir extensiones (EXE y DLL para tener volumen suficiente)
$extensiones = @("*.exe", "*.dll")

# 3. Buscar en todo el disco C: (Esto puede tardar unos minutos)
Write-Host "Iniciando búsqueda profunda en C:\... Esto llevará un tiempo." -ForegroundColor Cyan

Get-ChildItem -Path "C:\" -Include $extensiones -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { $_.Length -gt 0 -and $_.Length -lt 1MB } | 
    ForEach-Object {
        if ($contador -lt $maximo) {
            $nuevoNombre = "$contador" + "_" + $_.Name
            $rutaDestino = Join-Path $destino $nuevoNombre
            
            try {
                Copy-Item $_.FullName -Destination $rutaDestino -ErrorAction SilentlyContinue
                $contador++
                
                # Mostrar progreso cada 500 archivos
                if ($contador % 500 -eq 0) { Write-Host "Recolectados: $contador..." }
            } catch { }
        }
    }

Write-Host "¡Hecho! Se han recolectado $contador archivos en $destino" -ForegroundColor Green