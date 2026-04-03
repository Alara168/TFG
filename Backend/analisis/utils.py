import hashlib, math, pefile, joblib, torch, pandas as pd
from smda.Disassembler import Disassembler
from .ia_model import GatedAttentionMIL
from .models import LogActividad
import tempfile
import os
import pefile
import pandas as pd
from capstone import *
from capstone.x86 import *

# Carga perezosa del modelo para ahorrar memoria
_MODELO, _PIPELINE = None, None

def calcular_sha256(archivo):
    sha256 = hashlib.sha256()
    for chunk in archivo.chunks(): sha256.update(chunk)
    return sha256.hexdigest()

def calculate_entropy(data):
    if not data: return 0.0
    byte_counts = [0] * 256
    for byte in data: byte_counts[byte] += 1
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / len(data)
            entropy -= p * math.log2(p)
    return entropy

def get_resources():
    global _MODELO, _PIPELINE
    if _PIPELINE is None: _PIPELINE = joblib.load('mil_pipeline.pkl')
    if _MODELO is None:
        _MODELO = GatedAttentionMIL(len(_PIPELINE['feature_cols']), len(_PIPELINE['nombres']))
        _MODELO.load_state_dict(torch.load('best_model_gated_mil.pth', map_location='cpu'))
        _MODELO.eval()
    return _MODELO, _PIPELINE
def extract_features(archivo_django):
    archivo_django.seek(0)
    # Leemos el contenido completo una vez para extraer los bytes de las funciones después
    full_binary_data = archivo_django.read()
    archivo_django.seek(0)

    suffix = ".exe"
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    path = tmp_file.name
    
    try:
        for chunk in archivo_django.chunks():
            tmp_file.write(chunk)
        tmp_file.close()

        pe = pefile.PE(path, fast_load=True)
        disassembler = Disassembler()
        report = disassembler.disassembleFile(path)
        
        funciones = list(report.getFunctions()) if report else []
        if not funciones:
            return None, None

        opcodes = ['mov', 'add', 'sub', 'xor', 'cmp', 'test', 'lea', 'push', 'pop', 'call', 'jmp', 'ret']
        apis = ['CreateFile', 'WriteFile', 'OpenProcess', 'VirtualAlloc', 'CreateRemoteThread', 'RegOpenKey', 'InternetOpen', 'URLDownload', 'ShellExecute', 'WSAStartup', 'connect', 'bind', 'accept', 'HttpSendRequest', 'GetProcAddress', 'LoadLibrary']
        
        import_map = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        import_map[imp.address] = imp.name.decode('utf-8', 'ignore')

        features_list, addrs = [], []

        for function in funciones:
            instrs = list(function.getInstructions())
            if len(instrs) < 5: continue
            
            # --- ARREGLO 1: CÁLCULO DE ENTROPÍA REAL ---
            # Intentamos obtener los bytes de la función desde el binario original
            try:
                # SMDA nos da el offset y el tamaño aproximado sumando instrucciones
                f_offset = function.offset
                # Buscamos el offset físico en el archivo usando PE
                rva = f_offset - pe.OPTIONAL_HEADER.ImageBase
                raw_offset = pe.get_offset_from_rva(rva)
                
                # Estimamos el tamaño por la última instrucción
                last_ins = instrs[-1]
                f_size = (last_ins.offset + len(last_ins.bytes)) - f_offset
                
                func_bytes = full_binary_data[raw_offset : raw_offset + f_size]
                f_entropy = calculate_entropy(func_bytes)
            except:
                f_entropy = 0.0

            feat = {
                'num_instrs': len(instrs),
                'num_blocks': len(list(function.getBlocks())),
                'num_edges': len(list(function.getCodeInrefs())) + len(list(function.getCodeOutrefs())),
                'entropy': f_entropy, # <--- Ahora sí se guarda
                'api_calls_count': 0
            }
            
            # Inicializar contadores
            for op in opcodes: feat[f'opcode_{op}'] = 0
            for api in apis: feat[f'has_api_{api}'] = 0
            
            for ins in instrs:
                m = ins.mnemonic.lower()
                if m in opcodes: feat[f'opcode_{m}'] += 1
                
                # --- ARREGLO 2: CONTEO DE APIS ROBUSTO ---
                if m == 'call':
                    is_api = False
                    # Caso A: Referencia en import_map (IAT)
                    for ref in ins.getDataRefs():
                        if ref in import_map:
                            is_api = True
                            api_found = import_map[ref]
                            break
                    
                    # Caso B: SMDA ya resolvió el símbolo (si el reporte es rico)
                    if not is_api and hasattr(ins, 'symbol') and ins.symbol:
                        is_api = True
                        api_found = ins.symbol

                    if is_api:
                        feat['api_calls_count'] += 1
                        api_name_lower = api_found.lower()
                        for a in apis:
                            if a.lower() in api_name_lower:
                                feat[f'has_api_{a}'] = 1

            # Evitar división por cero
            total = len(instrs) if len(instrs) > 0 else 1
            feat['ratio_arithmetic'] = (feat['opcode_add'] + feat['opcode_sub'] + feat['opcode_xor']) / total
            feat['ratio_jumps'] = (feat['opcode_jmp'] + feat['opcode_call']) / total
            feat['cyclomatic_complexity'] = max(0, feat['num_edges'] - feat['num_blocks'] + 2)
            
            features_list.append(feat)
            addrs.append(hex(function.offset))

        return features_list, addrs

    except Exception as e:
        print(f"DEBUG Error en extracción: {str(e)}")
        return None, None
    finally:
        # Aseguramos el borrado del archivo temporal
        try:
            if os.path.exists(path):
                os.remove(path)
        except:
            pass # Si falla el borrado, no bloqueamos la respuesta del usuario

def registrar_log(user, accion, detalles="", request=None):
    ip = request.META.get('REMOTE_ADDR') if request else "0.0.0.0"
    LogActividad.objects.create(
        usuario=user if user.is_authenticated else None,
        accion=accion,
        detalles=detalles,
        ip_origen=ip
    )


def desensamblar_funcion(file_obj, func_addr):
    try:
        # Reiniciar cursor y leer datos
        file_obj.seek(0)
        data = file_obj.read()
        
        # Cargar PE para manejar mapeo de memoria
        pe = pefile.PE(data=data, fast_load=True)
        
        # Convertir dirección virtual a offset de archivo
        # 'get_offset_from_rva' es la clave aquí
        rva = int(func_addr, 16) - pe.OPTIONAL_HEADER.ImageBase
        file_offset = pe.get_offset_from_rva(rva)
        
        if file_offset is None:
            return f"Error: La dirección {func_addr} no es válida en este binario."
            
        # Desensamblar 128 bytes desde el offset
        code = data[file_offset : file_offset + 128]
        
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        output = []
        for i in md.disasm(code, int(func_addr, 16)):
            output.append(f"{i.mnemonic}\t{i.op_str}")
            
        return "\n".join(output)
        
    except Exception as e:
        return f"Error en descompilación: {str(e)}"