import os
import hashlib
import pandas as pd
import pefile
from smda.Disassembler import Disassembler

# CONFIGURACIÓN
MALWARE_FOLDER = "./muestras_malware/" # CAMBIA ESTO A TU RUTA
OUTPUT_CSV = "dataset_mil_features_pure.csv"

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

def get_import_mapping(pe):
    """
    Crea un mapa {Dirección_Memoria: Nombre_API} usando pefile.
    Esto nos permite saber a qué API llama una instrucción como 'CALL 0x402000'.
    """
    import_map = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    try:
                        name = imp.name.decode('utf-8')
                        # Mapeamos la dirección de la IAT (Import Address Table)
                        import_map[imp.address] = name
                    except:
                        continue
    return import_map

def analyze_binary(file_path):
    features_list = []
    file_hash = calculate_hash(file_path)
    filename = os.path.basename(file_path)
    
    print(f"[*] Procesando: {filename}...")

    try:
        # 1. Analizar Imports con PEfile
        pe = pefile.PE(file_path)
        import_map = get_import_mapping(pe)
        base_address = pe.OPTIONAL_HEADER.ImageBase
        
        # 2. Desensamblar y recuperar funciones con SMDA
        # SMDA lee el binario, encuentra funciones y crea el CFG
        with open(file_path, "rb") as f:
            binary_content = f.read()
        
        disassembler = Disassembler(config=None)
        # timeout=120 segundos por binario para evitar bloqueos en malware complejo
        report = disassembler.disassembleUnbuffer(binary_content, base_addr=base_address, timeout=120)

    except Exception as e:
        print(f"Error parseando {filename}: {e}")
        return []

    # Iterar sobre las funciones detectadas por SMDA
    for function in report.getFunctions():
        f_addr = function.offset
        f_instrs = function.getInstructions()
        
        # Estadísticas del CFG (Estructurales)
        num_blocks = len(function.getBlocks())
        num_edges = len(function.getCodeInRefs()) + len(function.getCodeOutRefs()) # Estimación de aristas
        
        # Diccionario de features
        feat = {
            'binary_hash': file_hash,
            'func_addr': hex(f_addr),
            'num_instrs': len(f_instrs),
            'num_blocks': num_blocks,
            'num_edges': num_edges,
            'cyclomatic_complexity': num_edges - num_blocks + 2, # Fórmula simple
            'api_calls_count': 0
        }

        # Inicializar contadores
        for op in INTERESTING_OPCODES:
            feat[f'opcode_{op}'] = 0
        for api in SUSPICIOUS_APIS:
            feat[f'has_api_{api}'] = 0

        # Analizar instrucciones una a una
        api_counter = 0
        
        for instr in f_instrs:
            # SMDA usa Capstone internamente. 'instr' tiene campos como mnemonic y operands
            mnemonic = instr.mnemonic.lower()
            
            # 1. Feature Sintáctica: Opcodes
            if mnemonic in INTERESTING_OPCODES:
                feat[f'opcode_{mnemonic}'] += 1

            # 2. Feature Semántica: Detección de APIs
            # Buscamos instrucciones CALL o JMP que apunten a direcciones en nuestro import_map
            if mnemonic in ['call', 'jmp']:
                # El operando suele ser una dirección o un puntero relativo
                # SMDA a veces facilita esto, pero chequeamos referencias
                offset = instr.offset
                
                # Obtener referencias (a qué llama esta instrucción)
                # En SMDA, necesitamos ver si la instrucción referencia una dirección de la IAT
                # Un truco rápido es mirar el string de desensamblado si la referencia no es directa
                op_str = instr.op_str
                
                # Chequeo heurístico de APIs
                found_api = False
                
                # Método A: Buscar en el mapa de imports por dirección absoluta (si es posible)
                # (Complejo en estático puro sin emulación, usamos strings como fallback)
                
                # Método B: Búsqueda de strings crudos (Efectivo y rápido)
                # Si el desensamblador resolvió el símbolo, aparecerá en op_str
                # Si no, miramos si pefile encontró imports y si coinciden offsets (avanzado)
                
                # Simplificación para TFG: Buscar nombres de API en los metadatos de imports
                # Si la función usa una dirección que machea con import_map
                # Nota: SMDA no siempre resuelve los punteros indirectos (jmp [0x4000]) automáticamente a texto.
                # Para solucionar esto robustamente en este script simple:
                
                # Verificamos si la instrucción hace referencia a datos
                if len(instr.data_refs) > 0:
                    for ref in instr.data_refs:
                        if ref in import_map:
                            api_name = import_map[ref]
                            api_counter += 1
                            for susp in SUSPICIOUS_APIS:
                                if susp.lower() in api_name.lower():
                                    feat[f'has_api_{susp}'] = 1
                                    
        feat['api_calls_count'] = api_counter
        
        # Ratios (Evitar división por cero)
        total = feat['num_instrs']
        if total > 0:
            feat['ratio_arithmetic'] = (feat['opcode_add'] + feat['opcode_sub'] + feat['opcode_xor']) / total
            feat['ratio_jumps'] = (feat['opcode_jmp'] + feat['opcode_call']) / total
        else:
            feat['ratio_arithmetic'] = 0
            feat['ratio_jumps'] = 0
            
        features_list.append(feat)

    return features_list

def main():
    if not os.path.exists(MALWARE_FOLDER):
        print("Error: Crea la carpeta de malware o ajusta la ruta.")
        return

    all_data = []
    files = [f for f in os.listdir(MALWARE_FOLDER) if os.path.isfile(os.path.join(MALWARE_FOLDER, f))]
    
    print(f"Total archivos: {len(files)}")

    for i, f in enumerate(files):
        path = os.path.join(MALWARE_FOLDER, f)
        res = analyze_binary(path)
        all_data.extend(res)
        
        if (i+1) % 5 == 0:
            print(f"Guardando parcial {i+1}...")
            pd.DataFrame(all_data).to_csv(OUTPUT_CSV, index=False)

    if all_data:
        df = pd.DataFrame(all_data)
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"¡Hecho! Dataset guardado en {OUTPUT_CSV}")
        print(df.head())
    else:
        print("No se extrajeron datos. Revisa si los binarios son ejecutables válidos.")

if __name__ == "__main__":
    main()