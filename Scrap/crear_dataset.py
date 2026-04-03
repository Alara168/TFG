import os
import hashlib
import pandas as pd
import pefile
import math
from smda.Disassembler import Disassembler

# ==========================================
# CONFIGURACIÓN Y CONSTANTES
# ==========================================
MALWARE_FOLDER = "ficheros/muestras_malware/"
BENIGN_FOLDER = "ficheros/muestras_benignas/" 
OUTPUT_CSV = "dataset_mil_features_pure.csv"
SAVE_EVERY_N = 10  # Guardar en el CSV cada 10 archivos nuevos procesados

# Opcodes que queremos contar en cada función
INTERESTING_OPCODES = ['mov', 'add', 'sub', 'xor', 'cmp', 'test', 'lea', 'push', 'pop', 'call', 'jmp', 'ret']
# APIs cuyo uso queremos detectar de forma específica
SUSPICIOUS_APIS = [
    'CreateFile', 'WriteFile', 'OpenProcess', 'VirtualAlloc', 
    'CreateRemoteThread', 'RegOpenKey', 'InternetOpen', 'URLDownload', 
    'ShellExecute', 'WSAStartup', 'connect', 'bind', 'accept', 'HttpSendRequest',
    'GetProcAddress', 'LoadLibrary'
]

def calculate_hash(file_path):
    """Calcula el SHA256 de un archivo para usarlo como identificador único."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for b in iter(lambda: f.read(4096), b""):
            sha256.update(b)
    return sha256.hexdigest()

def calculate_entropy(data):
    """Calcula la entropía de Shannon para medir qué tan 'aleatorio' o comprimido es un bloque de bytes."""
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    data_len = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)
    return entropy

def get_import_mapping(pe):
    """Extrae la tabla de importaciones para mapear direcciones de memoria con nombres de funciones API."""
    import_map = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    try:
                        name = imp.name.decode('utf-8')
                        import_map[imp.address] = name
                    except:
                        continue
    return import_map

def analyze_binary(file_path, is_malware, file_hash):
    features_list = []
    filename = os.path.basename(file_path)
    print(f"[*] Analizando: {filename}...")

    try:
        # 1. Cargar PE y mapa de importaciones
        pe = pefile.PE(file_path, fast_load=True)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        
        import_map = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', 'ignore')
                        import_map[imp.address] = api_name

        # 2. Leer contenido binario completo para la entropía
        with open(file_path, "rb") as f:
            full_binary_data = f.read()

        # 3. Desensamblar
        disassembler = Disassembler()
        report = disassembler.disassembleBuffer(full_binary_data, base_addr=image_base)
        if not report:
            pe.close()
            return []

        funciones = list(report.getFunctions())

        for function in funciones:
            instrs = list(function.getInstructions())
            if len(instrs) < 5: continue
            
            # --- Cálculo de Entropía (CORREGIDO) ---
            f_entropy = 0.0
            try:
                rva = function.offset - image_base
                raw_offset = pe.get_offset_from_rva(rva)
                if raw_offset is not None:
                    # Tamaño aproximado: dirección última instrucción + su tamaño - inicio
                    f_size = (instrs[-1].offset + len(instrs[-1].bytes)) - function.offset
                    func_bytes = full_binary_data[raw_offset : raw_offset + f_size]
                    f_entropy = calculate_entropy(func_bytes)
            except:
                pass

            # --- Inicializar Diccionario ---
            feat = {
                'binary_hash': file_hash,
                'func_addr': hex(function.offset),
                'num_instrs': float(len(instrs)), 
                'num_blocks': float(len(list(function.getBlocks()))),
                'num_edges': float(len(list(function.getCodeInrefs())) + len(list(function.getCodeOutrefs()))),
                'entropy': f_entropy,
                'api_calls_count': 0.0,
                'malware': is_malware
            }
            
            for op in INTERESTING_OPCODES: feat[f'opcode_{op}'] = 0.0
            for api in SUSPICIOUS_APIS: feat[f'has_api_{api}'] = 0.0

            # --- Procesar Instrucciones (Lógica Robusta) ---
            for ins in instrs:
                m = ins.mnemonic.lower()
                if m in INTERESTING_OPCODES: 
                    feat[f'opcode_{m}'] += 1.0
                
                if m in ['call', 'jmp']:
                    api_resolved = None
                    # A. Por Referencias de Datos (IAT)
                    for ref in ins.getDataRefs():
                        if ref in import_map:
                            api_resolved = import_map[ref]
                            break
                    
                    # B. Por RIP-Relative (Regex para x64)
                    if not api_resolved and "rip +" in ins.operands:
                        match = re.search(r'0x([0-9a-fA-F]+)', ins.operands)
                        if match:
                            offset = int(match.group(1), 16)
                            target = ins.offset + len(ins.bytes) + offset
                            if target in import_map: 
                                api_resolved = import_map[target]

                    # C. Por Símbolo (Si SMDA lo tiene)
                    if not api_resolved and hasattr(ins, 'symbol') and ins.symbol:
                        api_resolved = ins.symbol

                    if api_resolved:
                        feat['api_calls_count'] += 1.0
                        api_lower = api_resolved.lower()
                        for target in SUSPICIOUS_APIS:
                            if target.lower() in api_lower:
                                feat[f'has_api_{target}'] = 1.0

            # Ratios y Complejidad
            total = feat['num_instrs']
            feat['ratio_arithmetic'] = (feat['opcode_add'] + feat['opcode_sub'] + feat['opcode_xor']) / total
            feat['ratio_jumps'] = (feat['opcode_jmp'] + feat['opcode_call']) / total
            feat['cyclomatic_complexity'] = float(max(0, feat['num_edges'] - feat['num_blocks'] + 2))
            
            features_list.append(feat)

        pe.close()
        return features_list

    except Exception as e:
        print(f"Error en {filename}: {e}")
        return []

def save_to_csv(data_list):
    """
    Guarda los datos en el CSV. 
    Usa mode='a' (append) para no sobrescribir lo que ya existe.
    """
    if not data_list:
        return
        
    df = pd.DataFrame(data_list)
    file_exists = os.path.isfile(OUTPUT_CSV)
    
    # Si el archivo no existe, escribe cabecera (header=True).
    # Si ya existe, añade los datos sin repetir la cabecera (header=False).
    df.to_csv(OUTPUT_CSV, mode='a', index=False, header=not file_exists)
    print(f"    [GUARDADO] {len(data_list)} nuevas filas añadidas al dataset.")

def main():
    # 1. RECUPERAR PROGRESO: Leer hashes del archivo CSV si ya existe
    processed_hashes = set()
    if os.path.exists(OUTPUT_CSV):
        try:
            # Solo leemos la columna del hash para ahorrar memoria
            existing_df = pd.read_csv(OUTPUT_CSV, usecols=['binary_hash'])
            processed_hashes = set(existing_df['binary_hash'].unique())
            print(f"[*] Reanudando: {len(processed_hashes)} archivos ya detectados en el CSV.")
        except Exception as e:
            print(f"[!] No se pudo leer el CSV previo ({e}). Se creará uno nuevo.")

    folders_to_process = [
        (BENIGN_FOLDER, 0),
        (MALWARE_FOLDER, 1)
    ]

    new_data_buffer = []      # Acumula resultados antes de escribir a disco
    files_processed_count = 0  # Contador para el autoguardado

    for folder_path, label in folders_to_process:
        if not os.path.exists(folder_path):
            print(f"[-] Saltando {folder_path} (ruta no encontrada)")
            continue

        files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
        print(f"\n[+] Iniciando carpeta: {folder_path} ({len(files)} archivos)")

        for f in files:
            path = os.path.join(folder_path, f)
            
            # 2. SALTAR SI YA EXISTE: Calculamos hash antes de analizar
            current_hash = calculate_hash(path)
            if current_hash in processed_hashes:
                # Si el hash ya está en nuestro set, saltamos al siguiente archivo
                continue

            # Analizar el binario
            res = analyze_binary(path, label, current_hash)
            
            if res:
                new_data_buffer.extend(res)
                files_processed_count += 1
                # Añadir al set para evitar procesarlo de nuevo en esta misma ejecución si hubiera duplicados
                processed_hashes.add(current_hash)

            # 3. GUARDADO CADA X ARCHIVOS: Evita pérdida de datos si el script se corta
            if files_processed_count >= SAVE_EVERY_N:
                save_to_csv(new_data_buffer)
                new_data_buffer = []  # Vaciar la lista tras guardar
                files_processed_count = 0

    # Guardar cualquier dato restante en el buffer al finalizar
    if new_data_buffer:
        save_to_csv(new_data_buffer)
        print(f"\n[!] Finalizado con éxito.")
    else:
        print("\n[!] No se encontraron archivos nuevos para procesar.")

if __name__ == "__main__":
    main()