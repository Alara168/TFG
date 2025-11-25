import r2pipe
import os
import pandas as pd
import json
import hashlib

# CONFIGURACIÓN
# Cambia esto a la ruta de tus carpetas de malware
MALWARE_FOLDER = "./muestras_malware/"
OUTPUT_CSV = "dataset_mil_features.csv"

# LISTAS DE INTERÉS PARA FEATURES
INTERESTING_OPCODES = ['mov', 'add', 'sub', 'xor', 'cmp', 'test', 'lea', 'push', 'pop', 'call', 'jmp', 'nop']
# APIs sospechosas comunes (Features Semánticas) - Puedes ampliar esta lista
SUSPICIOUS_APIS = [
    'CreateFile', 'ReadFile', 'WriteFile', 'OpenProcess', 'VirtualAlloc', 
    'CreateRemoteThread', 'RegOpenKey', 'InternetOpen', 'URLDownload', 
    'ShellExecute', 'WSAStartup', 'connect', 'bind', 'accept'
]

def calculate_hash(file_path):
    """Calcula el SHA256 del fichero para identificarlo."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def analyze_binary(file_path):
    """Abre el binario, analiza y extrae features por función."""
    features_list = []
    file_hash = calculate_hash(file_path)
    
    print(f"[*] Analizando: {os.path.basename(file_path)}...")

    # Abrir binario con r2pipe
    # -2: Deshabilita stderr para limpieza
    try:
        r2 = r2pipe.open(file_path, flags=['-2'])
    except Exception as e:
        print(f"Error abriendo {file_path}: {e}")
        return []

    # COMANDOS RADARE2
    r2.cmd('aaa')  # Análisis profundo automático (analiza llamadas, saltos, símbolos)
    
    # Obtener lista de funciones en formato JSON
    # aflj: Analyze Functions List Json
    funcs = r2.cmdj('aflj')
    
    if not funcs:
        print("No se encontraron funciones (o binario corrupto).")
        r2.quit()
        return []

    for func in funcs:
        # Extraemos datos básicos que R2 ya nos da
        f_offset = func.get('offset', 0)
        f_name = func.get('name', 'unknown')
        f_size = func.get('size', 0)
        f_cc = func.get('cc', 0)   # Cyclomatic Complexity (Estructural)
        f_nbbs = func.get('nbbs', 0) # Number of Basic Blocks (Estructural)
        f_edges = func.get('edges', 0) # CFG Edges (Estructural)

        # Diccionario base de features para esta función
        func_features = {
            'binary_hash': file_hash,
            'func_addr': hex(f_offset),
            'func_name': f_name,
            # Features Sintácticas Básicas
            'size_bytes': f_size,
            'num_basic_blocks': f_nbbs,
            'cyclomatic_complexity': f_cc,
            'num_cfg_edges': f_edges,
            'num_instrs': 0, # Se llenará abajo
            'api_calls_count': 0
        }

        # Inicializar contadores de opcodes a 0
        for op in INTERESTING_OPCODES:
            func_features[f'opcode_{op}'] = 0
            
        # Inicializar presencia de APIs sospechosas a 0 (False)
        for api in SUSPICIOUS_APIS:
            func_features[f'has_api_{api}'] = 0

        # --- ANÁLISIS DETALLADO DE LA FUNCIÓN ---
        # pdfj: Print Disassembly Function Json (Desensambla la función actual)
        try:
            ops_data = r2.cmdj(f'pdfj @ {f_offset}')
        except:
            ops_data = None

        if ops_data and 'ops' in ops_data:
            instructions = ops_data['ops']
            func_features['num_instrs'] = len(instructions)
            
            call_counter = 0

            for instr in instructions:
                # 1. Feature Sintáctica: Conteo de Opcodes
                mnemonic = instr.get('type', '').lower() # mov, add, call...
                
                # A veces el tipo en r2 es 'upush' o similar, simplificamos
                if mnemonic in INTERESTING_OPCODES:
                    func_features[f'opcode_{mnemonic}'] += 1
                
                # 2. Feature Semántica: Detección de Llamadas a APIs
                # Si la instrucción es un CALL, miramos a dónde llama
                if 'call' in mnemonic:
                    call_counter += 1
                    # Disasm suele contener algo como "call sym.imp.CreateFileA"
                    disasm_str = instr.get('disasm', '')
                    
                    for suspicious in SUSPICIOUS_APIS:
                        if suspicious.lower() in disasm_str.lower():
                            func_features[f'has_api_{suspicious}'] = 1
                            # Nota: Podrías contar cuántas veces aparece, aquí usamos booleano (0/1)
            
            func_features['api_calls_count'] = call_counter

            # Features Derivadas (Ratios)
            total = func_features['num_instrs']
            if total > 0:
                func_features['ratio_arithmetic'] = (func_features['opcode_add'] + func_features['opcode_sub'] + func_features['opcode_xor']) / total
                func_features['ratio_calls'] = func_features['opcode_call'] / total
                func_features['ratio_jumps'] = (func_features['opcode_jmp'] + func_features['has_api_connect']) / total # Simplificado
            else:
                func_features['ratio_arithmetic'] = 0
                func_features['ratio_calls'] = 0
                func_features['ratio_jumps'] = 0

        features_list.append(func_features)
    
    r2.quit()
    return features_list

def main():
    all_data = []
    
    # Verificar directorio
    if not os.path.exists(MALWARE_FOLDER):
        print(f"Error: No existe el directorio {MALWARE_FOLDER}")
        return

    # Iterar sobre los archivos
    files = [f for f in os.listdir(MALWARE_FOLDER) if os.path.isfile(os.path.join(MALWARE_FOLDER, f))]
    
    print(f"Se encontraron {len(files)} archivos para procesar.")

    for i, filename in enumerate(files):
        path = os.path.join(MALWARE_FOLDER, filename)
        # Procesar binario
        binary_features = analyze_binary(path)
        all_data.extend(binary_features)
        
        # Guardado parcial cada 10 binarios (por seguridad)
        if (i + 1) % 10 == 0:
             print(f"--- Guardando progreso parcial ({i+1}/{len(files)}) ---")
             df_partial = pd.DataFrame(all_data)
             df_partial.to_csv(OUTPUT_CSV, index=False)

    # Guardado final
    if all_data:
        df = pd.DataFrame(all_data)
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"\n[OK] Extracción completada. Dataset guardado en: {OUTPUT_CSV}")
        print(f"Dimensiones del dataset: {df.shape} (Filas: Funciones, Columnas: Features)")
    else:
        print("No se extrajeron datos.")

if __name__ == "__main__":
    main()