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
    """
    Analiza un binario individual, desensambla sus funciones y extrae
    características estructurales, sintácticas y semánticas.
    """
    features_list = []
    filename = os.path.basename(file_path)
    
    print(f"[*] Analizando: {filename}...")

    try:
        # Carga rápida del archivo PE (Portable Executable)
        pe = pefile.PE(file_path, fast_load=True)
        if not pe.is_exe() and not pe.is_dll():
            return []
            
        import_map = get_import_mapping(pe)
        base_address = pe.OPTIONAL_HEADER.ImageBase
        
        with open(file_path, "rb") as f:
            binary_content = f.read()
        
        # Uso del motor SMDA para desensamblado recursivo
        disassembler = Disassembler(config=None)
        report = disassembler.disassembleBuffer(binary_content, base_addr=base_address)

        if report is None:
            return []

        # Procesar cada función identificada por el desensamblador
        for function in report.getFunctions():
            f_addr = function.offset
            f_instrs = list(function.getInstructions())
            basic_blocks = list(function.getBlocks())
            
            if not f_instrs:
                continue 

            # Cálculo de la longitud física de la función en bytes
            function_len = sum(instr.detailed.size for instr in f_instrs if hasattr(instr.detailed, 'size'))
            
            if function_len <= 0:
                continue
            
            # Extraer los bytes reales de la función para calcular su entropía
            f_start = f_addr - base_address 
            f_end = min(f_start + function_len, len(binary_content))
            
            if f_start >= f_end or f_start < 0:
                continue
            
            function_bytes = binary_content[f_start:f_end]
            entropy_value = calculate_entropy(function_bytes)

            # Características estructurales del Grafo de Flujo de Control (CFG)
            num_blocks = len(basic_blocks)
            num_edges = len(list(function.getCodeInrefs())) + len(list(function.getCodeOutrefs()))
            
            # Diccionario base de la función
            feat = {
                'binary_hash': file_hash,
                'func_addr': hex(f_addr),
                'num_instrs': len(f_instrs),
                'num_blocks': num_blocks,
                'num_edges': num_edges,
                'cyclomatic_complexity': num_edges - num_blocks + 2,
                'api_calls_count': 0,
                'entropy': entropy_value,
                'malware': is_malware
            }

            # Inicializar contadores de Opcodes y flags de APIs
            for op in INTERESTING_OPCODES:
                feat[f'opcode_{op}'] = 0
            for api in SUSPICIOUS_APIS:
                feat[f'has_api_{api}'] = 0

            api_counter = 0
            for instr in f_instrs:
                mnemonic = instr.mnemonic.lower()
                
                # Conteo de opcodes interesantes
                if mnemonic in INTERESTING_OPCODES:
                    feat[f'opcode_{mnemonic}'] += 1

                # Análisis de llamadas (CALL/JMP) para identificar uso de APIs
                if mnemonic in ['call', 'jmp']:
                    references = list(instr.getDataRefs())
                    for ref in references:
                        if ref in import_map:
                            api_name = import_map[ref]
                            api_counter += 1
                            # Verificar si la API llamada está en nuestra lista de sospechosas
                            for susp in SUSPICIOUS_APIS:
                                if susp.lower() in api_name.lower():
                                    feat[f'has_api_{susp}'] = 1
            
            feat['api_calls_count'] = api_counter
            
            # Cálculo de proporciones (Ratios)
            total = feat['num_instrs']
            if total > 0:
                feat['ratio_arithmetic'] = (feat['opcode_add'] + feat['opcode_sub'] + feat['opcode_xor']) / total
                feat['ratio_jumps'] = (feat['opcode_jmp'] + feat['opcode_call']) / total
            else:
                feat['ratio_arithmetic'] = 0
                feat['ratio_jumps'] = 0
                
            features_list.append(feat)

    except Exception as e:
        print(f"Error procesando {filename}: {e}")
        return []

    return features_list

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