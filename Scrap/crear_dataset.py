import os
import hashlib
import pandas as pd
import pefile
import math
from smda.Disassembler import Disassembler

# CONFIGURACIÓN
MALWARE_FOLDER = "ficheros/muestras_malware/"
BENIGN_FOLDER = "ficheros/muestras_benignas/" 
OUTPUT_CSV = "dataset_mil_features_pure.csv"
SAVE_EVERY_N = 10  # Guardar cada X archivos nuevos procesados

# LISTAS DE INTERÉS
INTERESTING_OPCODES = ['mov', 'add', 'sub', 'xor', 'cmp', 'test', 'lea', 'push', 'pop', 'call', 'jmp', 'ret']
SUSPICIOUS_APIS = [
    'CreateFile', 'WriteFile', 'OpenProcess', 'VirtualAlloc', 
    'CreateRemoteThread', 'RegOpenKey', 'InternetOpen', 'URLDownload', 
    'ShellExecute', 'WSAStartup', 'connect', 'bind', 'accept', 'HttpSendRequest',
    'GetProcAddress', 'LoadLibrary'
]

def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for b in iter(lambda: f.read(4096), b""):
            sha256.update(b)
    return sha256.hexdigest()

def calculate_entropy(data):
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
        pe = pefile.PE(file_path, fast_load=True)
        if not pe.is_exe() and not pe.is_dll():
            return []
        import_map = get_import_mapping(pe)
        base_address = pe.OPTIONAL_HEADER.ImageBase
        
        with open(file_path, "rb") as f:
            binary_content = f.read()
        
        disassembler = Disassembler(config=None)
        report = disassembler.disassembleBuffer(binary_content, base_addr=base_address)

        if report is None:
            return []

        for function in report.getFunctions():
            f_addr = function.offset
            f_instrs = list(function.getInstructions())
            basic_blocks = list(function.getBlocks())
            
            function_len = 0
            if not f_instrs:
                continue 

            try:
                for instr in f_instrs:
                    function_len += instr.detailed.size
            except AttributeError:
                continue
            
            if function_len <= 0:
                continue
            
            f_start = f_addr - base_address 
            f_end = f_start + function_len 

            if f_end > len(binary_content):
                f_end = len(binary_content)
            
            if f_start >= f_end or f_start < 0:
                continue
            
            function_bytes = binary_content[f_start:f_end]
            entropy_value = calculate_entropy(function_bytes)

            num_blocks = len(basic_blocks)
            num_edges = len(list(function.getCodeInrefs())) + len(list(function.getCodeOutrefs()))
            
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

            for op in INTERESTING_OPCODES:
                feat[f'opcode_{op}'] = 0
            for api in SUSPICIOUS_APIS:
                feat[f'has_api_{api}'] = 0

            api_counter = 0
            for instr in f_instrs:
                mnemonic = instr.mnemonic.lower()
                if mnemonic in INTERESTING_OPCODES:
                    feat[f'opcode_{mnemonic}'] += 1

                if mnemonic in ['call', 'jmp']:
                    references = list(instr.getDataRefs())
                    for ref in references:
                        if ref in import_map:
                            api_name = import_map[ref]
                            api_counter += 1
                            for susp in SUSPICIOUS_APIS:
                                if susp.lower() in api_name.lower():
                                    feat[f'has_api_{susp}'] = 1
            
            feat['api_calls_count'] = api_counter
            total = feat['num_instrs']
            if total > 0:
                feat['ratio_arithmetic'] = (feat['opcode_add'] + feat['opcode_sub'] + feat['opcode_xor']) / total
                feat['ratio_jumps'] = (feat['opcode_jmp'] + feat['opcode_call']) / total
            else:
                feat['ratio_arithmetic'] = 0
                feat['ratio_jumps'] = 0
                
            features_list.append(feat)

    except Exception as e:
        print(f"Error en {filename}: {e}")
        return []

    return features_list

def main():
    # 1. Cargar hashes procesados previamente
    processed_hashes = set()
    if os.path.exists(OUTPUT_CSV):
        try:
            existing_df = pd.read_csv(OUTPUT_CSV, usecols=['binary_hash'])
            processed_hashes = set(existing_df['binary_hash'].unique())
            print(f"[*] Reanudando: {len(processed_hashes)} archivos ya procesados.")
        except Exception as e:
            print(f"[!] No se pudo leer el CSV previo, empezando de cero. ({e})")

    folders_to_process = [
        (BENIGN_FOLDER, 0),
        (MALWARE_FOLDER, 1)
    ]

    new_data_buffer = []
    files_since_last_save = 0

    for folder_path, label in folders_to_process:
        if not os.path.exists(folder_path):
            continue

        files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
        print(f"\n[+] Carpeta: {folder_path} ({len(files)} archivos)")

        for f in files:
            path = os.path.join(folder_path, f)
            
            # 2. Calcular hash antes de analizar para decidir si saltar
            current_hash = calculate_hash(path)
            if current_hash in processed_hashes:
                continue

            res = analyze_binary(path, label, current_hash)
            if res:
                new_data_buffer.extend(res)
                files_since_last_save += 1
                processed_hashes.add(current_hash)

            # 3. Guardado incremental
            if files_since_last_save >= SAVE_EVERY_N:
                save_to_csv(new_data_buffer)
                new_data_buffer = [] # Limpiar buffer tras guardar
                files_since_last_save = 0

    # Guardar restos finales
    if new_data_buffer:
        save_to_csv(new_data_buffer)
        print(f"\n[!] ¡Hecho! Proceso completado.")
    else:
        print("\n[!] No había archivos nuevos para procesar.")

def save_to_csv(data_list):
    """Guarda los datos en modo append si el archivo ya existe."""
    df = pd.DataFrame(data_list)
    file_exists = os.path.isfile(OUTPUT_CSV)
    
    # mode='a' para añadir al final, header=False si el archivo ya tiene cabeceras
    df.to_csv(OUTPUT_CSV, mode='a', index=False, header=not file_exists)
    print(f"    [OK] Guardado incremental de {len(data_list)} funciones.")

if __name__ == "__main__":
    main()