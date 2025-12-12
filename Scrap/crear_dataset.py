import os
import hashlib
import pandas as pd
import pefile
import math
from smda.Disassembler import Disassembler

# CONFIGURACIÓN
MALWARE_FOLDER = "ficheros/muestras_malware/" 
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

def calculate_entropy(data):
    """
    Calcula la entropía de Shannon de un bloque de bytes.
    La entropía máxima es 8 bits/byte para un flujo de datos aleatorio.
    """
    if not data:
        return 0.0
    
    # 1. Calcular las frecuencias de cada byte (0-255)
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
        
    data_len = len(data)
    entropy = 0.0
    
    # 2. Aplicar la fórmula de la Entropía de Shannon: 
    # H = - sum(p_i * log2(p_i))
    # Donde p_i es la probabilidad de que ocurra el byte i.
    for count in byte_counts:
        if count > 0:
            probability = count / data_len
            entropy -= probability * math.log2(probability)
            
    return entropy


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
        with open(file_path, "rb") as f:
            binary_content = f.read()
        
        disassembler = Disassembler(config=None)
        report = disassembler.disassembleBuffer(binary_content, base_addr=base_address)

        if report is None:
            print(f"[-] SMDA falló en el análisis (Reporte Nulo): {filename}")
            return []

        # Iterar sobre las funciones detectadas por SMDA
        for function in report.getFunctions():
            f_addr = function.offset
            f_instrs = list(function.getInstructions())
            basic_blocks = list(function.getBlocks())

           # CÁLCULO DE ENTROPÍA Y LONGITUD
            function_len = 0
            
            if not f_instrs:
                continue # Saltar funciones sin instrucciones

            try:
                # La longitud de la función se calcula sumando el tamaño de todas sus instrucciones.
                for instr in f_instrs:
                    # Acceso directo y confirmado: 'instr.detailed.size'
                    function_len += instr.detailed.size
            except AttributeError as e:
                # Si una instrucción no tiene 'detailed.size', saltamos la función.
                print(f"  [!] Fallo de atributo ({e}) al sumar longitud en la función {hex(f_addr)}. Saltando.")
                continue
            
            # Sanity check: Si la longitud calculada es cero o negativa
            if function_len <= 0:
                continue
            
            # Obtener los bytes de la función del contenido binario original
            f_start = f_addr - base_address 
            f_end = f_start + function_len 

            # Sanity check: Asegurarse de no exceder los límites del archivo
            if f_end > len(binary_content):
                f_end = len(binary_content)
            
            if f_start >= f_end or f_start < 0:
                continue
            
            function_bytes = binary_content[f_start:f_end]
            
            # Calcular la entropía de esos bytes
            entropy_value = calculate_entropy(function_bytes)


            # Estadísticas del CFG (Estructurales)
            num_blocks = len(basic_blocks)
            num_edges = len(list(function.getCodeInrefs())) + len(list(function.getCodeOutrefs()))
            
            # Diccionario de features
            feat = {
                'binary_hash': file_hash,
                'func_addr': hex(f_addr),
                'num_instrs': len(f_instrs),
                'num_blocks': num_blocks,
                'num_edges': num_edges,
                'cyclomatic_complexity': num_edges - num_blocks + 2, # Fórmula simple
                'api_calls_count': 0,
                'entropy': entropy_value
            }

            # Inicializar contadores
            for op in INTERESTING_OPCODES:
                feat[f'opcode_{op}'] = 0
            for api in SUSPICIOUS_APIS:
                feat[f'has_api_{api}'] = 0

            # Analizar instrucciones una a una
            api_counter = 0
            
            for instr in f_instrs:
                mnemonic = instr.mnemonic.lower()
                
                # 1. Feature Sintáctica: Opcodes
                if mnemonic in INTERESTING_OPCODES:
                    feat[f'opcode_{mnemonic}'] += 1

                # 2. Feature Semántica: Detección de APIs
                if mnemonic in ['call', 'jmp']:
                    references = list(instr.getDataRefs())
                    if len(references) > 0:
                        for ref in references:
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

    except Exception as e:
        print(f"Error irrecuperable en {filename}: {e}")
        return []

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
        if (i > 20):
            break

    if all_data:
        df = pd.DataFrame(all_data)
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"¡Hecho! Dataset guardado en {OUTPUT_CSV}")
        print(df.head())
    else:
        print("No se extrajeron datos. Revisa si los binarios son ejecutables válidos.")

if __name__ == "__main__":
    main()