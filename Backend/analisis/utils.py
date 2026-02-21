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
    # Creamos el archivo temporal manualmente para controlar el cierre
    suffix = ".exe"
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    path = tmp_file.name
    
    try:
        # 1. Escribir y cerrar el archivo inmediatamente para que SMDA pueda abrirlo
        for chunk in archivo_django.chunks():
            tmp_file.write(chunk)
        tmp_file.close() # <--- CRÍTICO para evitar PermissionError en Windows

        # 2. Cargar PE y Desensamblar
        pe = pefile.PE(path, fast_load=True)
        disassembler = Disassembler()
        report = disassembler.disassembleFile(path)
        
        # 3. Extraer funciones (forma compatible con versiones antiguas y nuevas de SMDA)
        funciones = list(report.getFunctions()) if report else []
        
        if not funciones:
            print("DEBUG: SMDA no identificó funciones.")
            return None, None

        # --- Parámetros del modelo (36 columnas) ---
        opcodes = ['mov', 'add', 'sub', 'xor', 'cmp', 'test', 'lea', 'push', 'pop', 'call', 'jmp', 'ret']
        apis = ['CreateFile', 'WriteFile', 'OpenProcess', 'VirtualAlloc', 'CreateRemoteThread', 'RegOpenKey', 'InternetOpen', 'URLDownload', 'ShellExecute', 'WSAStartup', 'connect', 'bind', 'accept', 'HttpSendRequest', 'GetProcAddress', 'LoadLibrary']
        
        import_map = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        import_map[imp.address] = imp.name.decode('utf-8', 'ignore')

        features_list, addrs = [] , []

        for function in funciones:
            instrs = list(function.getInstructions())
            if len(instrs) < 5: continue
            
            feat = {
                'num_instrs': len(instrs),
                'num_blocks': len(list(function.getBlocks())),
                'num_edges': len(list(function.getCodeInrefs())) + len(list(function.getCodeOutrefs())),
                'entropy': 0.0,
                'api_calls_count': 0
            }
            feat['cyclomatic_complexity'] = feat['num_edges'] - feat['num_blocks'] + 2
            
            for op in opcodes: feat[f'opcode_{op}'] = 0
            for api in apis: feat[f'has_api_{api}'] = 0
            
            for ins in instrs:
                m = ins.mnemonic.lower()
                if m in opcodes: feat[f'opcode_{m}'] += 1
                if m in ['call', 'jmp']:
                    for ref in ins.getDataRefs():
                        if ref in import_map:
                            feat['api_calls_count'] += 1
                            api_name = import_map[ref].lower()
                            for a in apis:
                                if a.lower() in api_name: feat[f'has_api_{a}'] = 1
            
            total = len(instrs)
            feat['ratio_arithmetic'] = (feat['opcode_add'] + feat['opcode_sub'] + feat['opcode_xor']) / total
            feat['ratio_jumps'] = (feat['opcode_jmp'] + feat['opcode_call']) / total
            
            features_list.append(feat)
            addrs.append(hex(function.offset))

        print(f"DEBUG: Éxito. {len(features_list)} funciones listas para la IA.")
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
        output = [f"--- Desensamblado en {func_addr} ---"]
        for i in md.disasm(code, int(func_addr, 16)):
            output.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
            
        return "\n".join(output)
        
    except Exception as e:
        return f"Error en descompilación: {str(e)}"