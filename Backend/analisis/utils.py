import hashlib, math, pefile, joblib, torch, pandas as pd
from smda.Disassembler import Disassembler
from .ia_model import GatedAttentionMIL
from .models import LogActividad
import tempfile
import os, traceback
import pefile
import pandas as pd
from capstone import *
from capstone.x86 import *
import os, tempfile, pefile, traceback, re
from smda.Disassembler import Disassembler

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
    full_binary_data = archivo_django.read()
    archivo_django.seek(0)

    fd, path = tempfile.mkstemp(suffix=".exe")
    try:
        with os.fdopen(fd, 'wb') as tmp:
            for chunk in archivo_django.chunks():
                tmp.write(chunk)

        pe = pefile.PE(path)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        
        disassembler = Disassembler()
        report = disassembler.disassembleFile(path)
        funciones = list(report.getFunctions()) if report else []
        
        if not funciones:
            pe.close()
            return None, None

        # --- MAPA DE IAT ---
        import_map = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', 'ignore')
                        import_map[imp.address] = api_name
                        if hasattr(imp, 'hint_name_table_rva') and imp.hint_name_table_rva:
                            import_map[imp.hint_name_table_rva + image_base] = api_name

        opcodes = ['mov', 'add', 'sub', 'xor', 'cmp', 'test', 'lea', 'push', 'pop', 'call', 'jmp', 'ret']
        apis_to_track = ['CreateFile', 'WriteFile', 'OpenProcess', 'VirtualAlloc', 'CreateRemoteThread', 
                         'RegOpenKey', 'InternetOpen', 'URLDownload', 'ShellExecute', 'WSAStartup', 
                         'connect', 'bind', 'accept', 'HttpSendRequest', 'GetProcAddress', 'LoadLibrary']
        
        features_list, addrs = [], []

        for function in funciones:
            instrs = list(function.getInstructions())
            if len(instrs) < 5: continue
            
            # Inicializamos el diccionario de la función
            feat = {
                'num_instrs': float(len(instrs)), 
                'num_blocks': float(len(list(function.getBlocks()))),
                'num_edges': float(len(list(function.getCodeInrefs())) + len(list(function.getCodeOutrefs()))),
                'entropy': 0.0,
                'api_calls_count': 0.0
            }
            # Pre-llenar opcodes y apis en 0
            for op in opcodes: feat[f'opcode_{op}'] = 0.0
            for api in apis_to_track: feat[f'has_api_{api}'] = 0.0

            # --- Cálculo de Entropía ---
            try:
                rva = function.offset - image_base
                raw_offset = pe.get_offset_from_rva(rva)
                if raw_offset is not None:
                    f_size = (instrs[-1].offset + len(instrs[-1].bytes)) - function.offset
                    func_bytes = full_binary_data[raw_offset : raw_offset + f_size]
                    feat['entropy'] = calculate_entropy(func_bytes)
            except: pass

            # --- Procesar Instrucciones ---
            for ins in instrs:
                m = ins.mnemonic.lower()
                if m in opcodes: feat[f'opcode_{m}'] += 1.0
                
                api_resolved = None
                # 1. Por IAT (Convertimos generador a lista para debug/itera)
                refs = list(ins.getDataRefs())
                for ref in refs:
                    if ref in import_map:
                        api_resolved = import_map[ref]
                        break
                
                # 2. Por RIP-Relative
                if not api_resolved and "rip +" in ins.operands:
                    try:
                        match = re.search(r'0x([0-9a-fA-F]+)', ins.operands)
                        if match:
                            offset = int(match.group(1), 16)
                            target = ins.offset + len(ins.bytes) + offset
                            if target in import_map: 
                                api_resolved = import_map[target]
                    except: pass
                
                # 3. Por Símbolo
                if not api_resolved and hasattr(ins, 'symbol') and ins.symbol:
                    api_resolved = ins.symbol

                # --- Marcado de coincidencia ---
                if api_resolved:
                    feat['api_calls_count'] += 1.0
                    api_lower = api_resolved.lower()
                    for target in apis_to_track:
                        if target.lower() in api_lower:
                            feat[f'has_api_{target}'] = 1.0

            # Ratios finales
            total = feat['num_instrs'] if feat['num_instrs'] > 0 else 1.0
            feat['ratio_arithmetic'] = (feat['opcode_add'] + feat['opcode_sub'] + feat['opcode_xor']) / total
            feat['ratio_jumps'] = (feat['opcode_jmp'] + feat['opcode_call']) / total
            feat['cyclomatic_complexity'] = float(max(0, feat['num_edges'] - feat['num_blocks'] + 2))
            
            # GUARDAR COPIA DEL DICCIONARIO
            features_list.append(feat.copy())
            addrs.append(hex(function.offset))

        pe.close()
        return features_list, addrs

    except Exception:
        traceback.print_exc()
        return None, None
    finally:
        if os.path.exists(path):
            try: os.remove(path)
            except: pass

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