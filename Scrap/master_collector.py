import os
import requests
import json
import time
import csv
import signal 
import subprocess 
from dotenv import load_dotenv
import sys 

# ==============================================================================
#                      DESCRIPCIÓN DEL FLUJO DE TRABAJO (TFG)
# ==============================================================================
"""
Este script realiza el proceso completo de recolección y filtrado de hashes de malware
para el TFG, garantizando la reanudación ante interrupciones y la limitación de muestras.

Pasos ejecutados:

1.  DESCARGA DE HASHES (GitHub): Descarga todos los archivos .txt de la carpeta SHA256 
    del repositorio de GitHub en un directorio temporal (github_hashes_temp).

2.  CONCATENACIÓN Y LIMPIEZA INICIAL: Combina todos los hashes únicos en un único archivo 
    maestro (MASTER_SHA256_LIST.txt) dentro de la carpeta Scrap/ficheros.
    Luego, borra los archivos temporales de GitHub y la carpeta temporal.

3.  FILTRADO (MalwareBazaar API):
    a. Consulta la API de MalwareBazaar con 'get_info' para cada hash.
    b. Limita la recolección a un objetivo de 40,000 hashes con la etiqueta "exe".
    c. Guarda los resultados en un archivo CSV (hashes_exe.csv) separado por ';', 
       registrando el HASH, la SIGNATURE y los TAGS.
    d. Implementa una pausa optimizada de 0.5 segundos entre solicitudes.
    e. Incluye manejo de errores para evitar que la ejecución se detenga por respuestas malformadas.

4.  REANUDACIÓN: Si el script falla o se interrumpe, detecta el último hash escrito en 
    hashes_exe.csv y continúa el proceso desde ese punto en el archivo maestro.

5.  LIMPIEZA FINAL: Una vez que el filtrado finaliza o alcanza el límite, el archivo 
    maestro MASTER_SHA256_LIST.txt es borrado.

6. COMMIT Y PUSH AUTOMÁTICO:
    a. Se usa un bloque try-finally para garantizar que, si el script finaliza 
       (normalmente o por error/interrupción), se ejecuten las operaciones de limpieza.
    b. Se crea un commit local con el progreso actual (archivos hashes_exe.csv y maestro).
    c. Se hace push a GitHub para guardar el progreso de forma remota.

Todos los archivos finales se guardan en el directorio 'Scrap/ficheros'.
"""
# ==============================================================================

# --- 1. CONFIGURACIÓN Y CONSTANTES ---

load_dotenv()
API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")

# Rutas y URLs
MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
GITHUB_API_URL = "https://api.github.com/repos/aaryanrlondhe/Malware-Hash-Database/contents/SHA256"

# Directorios (Calculados relativos al script)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "ficheros")
DOWNLOAD_DIR = os.path.join(BASE_DIR, "github_hashes_temp")

# Nombres de archivos y rutas completas
MASTER_HASH_FILE = os.path.join(OUTPUT_DIR, "MASTER_SHA256_LIST.txt")
OUTPUT_EXE_FILE = os.path.join(OUTPUT_DIR, "hashes_exe.csv") 

# Parámetros de la API
TARGET_TAG = "exe"
REQUEST_DELAY = 0.5 
TARGET_EXE_COUNT = 70000 

# Variables de estado global para el manejador de señales
global_state = {'interrupted': False, 'count': 0}

# ------------------------------------------------------------------------------

# --- 2. FUNCIONES DE GITHUB Y CONCATENACIÓN ---

def descargar_archivos_de_github(api_url: str, download_dir: str):
    """Descarga todos los archivos .txt de la carpeta de GitHub."""
    if not os.path.exists(download_dir):
        os.makedirs(download_dir)
        print(f"📁 Creado directorio temporal: {download_dir}")

    print(f"\n🔎 Obteniendo lista de archivos desde GitHub...")
    archivos_descargados = []
    
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        files_list = response.json()
        
        for item in files_list:
            if item['type'] == 'file' and item['name'].endswith('.txt'):
                filename = item['name']
                raw_url = item['download_url'] 

                if raw_url:
                    print(f"⬇️ Descargando {filename}...")
                    file_response = requests.get(raw_url, stream=True)
                    file_response.raise_for_status()
                    
                    output_path = os.path.join(download_dir, filename)
                    with open(output_path, 'wb') as f:
                        for chunk in file_response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    archivos_descargados.append(output_path)
        return archivos_descargados

    except requests.exceptions.RequestException as e:
        print(f"❌ Error al conectar con la API de GitHub: {e}")
        return []

def concatenar_y_limpiar_archivos(file_paths: list, master_output_file: str, download_dir: str):
    """Concatena los archivos, elimina duplicados y borra los archivos temporales."""
    if not file_paths:
        print("⚠️ No hay archivos para concatenar.")
        return
    
    if not os.path.exists(os.path.dirname(master_output_file)):
        os.makedirs(os.path.dirname(master_output_file))

    print(f"\n🔗 Concatenando {len(file_paths)} archivos...")
    hash_set = set() 
    
    try:
        for file_path in file_paths:
            with open(file_path, 'r', encoding='utf-8') as infile:
                for line in infile:
                    hash_value = line.strip().lower() 
                    if hash_value and len(hash_value) == 64:
                        hash_set.add(hash_value)

        with open(master_output_file, 'w', encoding='utf-8') as outfile:
            for hash_value in sorted(list(hash_set)):
                outfile.write(hash_value + '\n')
        
        print(f"💾 Se guardaron {len(hash_set)} hashes únicos en {os.path.basename(master_output_file)}.")

        print(f"🧹 Limpiando archivos temporales de GitHub...")
        for file_path in file_paths:
            os.remove(file_path)
        os.rmdir(download_dir)
        print("✅ Limpieza completada.")

    except Exception as e:
        print(f"❌ Error durante la concatenación/limpieza: {e}")
        
# ------------------------------------------------------------------------------

# --- 3. FUNCIONES DE GIT (ACTUALIZADO) ---

def ejecutar_comando_git(comando: list, cwd: str) -> bool:
    """Ejecuta un comando de Git en el directorio raíz del TFG (cwd)."""
    try:
        resultado = subprocess.run(
            comando, 
            cwd=cwd, 
            check=True, 
            capture_output=True, 
            text=True
        )
        # Ignorar 'Nothing to commit' para permitir el push
        if "nothing to commit" in resultado.stdout.lower():
            return False 
            
        print(f"✅ Git OK: {comando[1]} | {resultado.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        # Esto sucede si el push falla o hay un error de PAT/credenciales.
        print(f"❌ Git ERROR al ejecutar '{' '.join(comando)}':")
        print(f"   Stderr: {e.stderr.strip()}")
        return False
    except FileNotFoundError:
        print("❌ Error: Git no se encontró. Asegúrate de que esté instalado y en PATH.")
        return False

def manejar_limpieza_y_push(finished_all_hashes: bool, current_exe_count: int):
    """
    Realiza la limpieza condicional del fichero maestro y hace el commit y push de TODOS los archivos.
    """
    # Asume que la raíz del repositorio es un nivel superior a la carpeta 'Scrap'
    root_dir = os.path.dirname(BASE_DIR) 

    print("\n--- 7. COMMIT Y PUSH AUTOMÁTICO ---")
    
    # 1. Añadir TODOS los archivos modificados/creados ('git add .')
    # Esto asegura que los scripts, logs y hashes sean incluidos.
    print("➕ Añadiendo todos los archivos modificados al staging...")
    ejecutar_comando_git(["git", "add", "."], root_dir)
    
    # 2. Manejo de la limpieza condicional del archivo maestro
    if finished_all_hashes and current_exe_count >= TARGET_EXE_COUNT and os.path.exists(MASTER_HASH_FILE):
        print(f"\n🗑️ LÍMITE ALCANZADO. Borrando fichero maestro: {os.path.basename(MASTER_HASH_FILE)}")
        
        # Eliminar el archivo físicamente
        try:
            os.remove(MASTER_HASH_FILE)
            print("✅ Fichero maestro borrado correctamente.")
        except Exception as e:
            print(f"❌ No se pudo borrar el fichero maestro: {e}")
            
        # Ejecutar 'git rm' para registrar la eliminación en Git (si estaba rastreado)
        ejecutar_comando_git(["git", "rm", "-f", os.path.relpath(MASTER_HASH_FILE, root_dir)], root_dir)
    elif os.path.exists(MASTER_HASH_FILE):
        print(f"✅ Maestro persiste: Aún no se alcanza el límite ({current_exe_count}/{TARGET_EXE_COUNT}).")


    # 3. Crear mensaje de commit
    commit_msg = f"PROGRESO: {current_exe_count} hashes EXE recolectados."
    if current_exe_count >= TARGET_EXE_COUNT:
         commit_msg = f"FINALIZADO: Objetivo de {TARGET_EXE_COUNT} hashes EXE alcanzado."
    
    # 4. Crear el Commit
    if ejecutar_comando_git(["git", "commit", "-m", commit_msg], root_dir):
        # 5. Hacer Push a GitHub (Solo si el commit fue exitoso)
        print("\n📤 Intentando hacer push a GitHub...")
        ejecutar_comando_git(["git", "push", "origin", "main"], root_dir)
    else:
        print("⚠️ No hay cambios detectados para hacer commit/push. Progreso guardado localmente.")

# ------------------------------------------------------------------------------

# --- 4. FUNCIONES DE FILTRADO Y REANUDACIÓN (Mantenidas) ---

def obtener_punto_de_reanudacion(master_file: str, output_file: str) -> tuple[str | None, int]:
    """Determina el último hash procesado y el número de muestras EXE ya recolectadas."""
    if not os.path.exists(output_file):
        return None, 0
    try:
        current_exe_count = 0
        last_hash = None
        with open(output_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f, delimiter=';')
            try:
                header = next(reader)
            except StopIteration:
                return None, 0 
            for row in reader:
                if row:
                    last_hash = row[0] 
                    current_exe_count += 1
        if last_hash:
            print(f"\n⏳ Archivo CSV encontrado. {current_exe_count} EXE recolectados. Último hash procesado: {last_hash}")
            with open(master_file, 'r', encoding='utf-8') as master:
                for i, line in enumerate(master):
                    if line.strip().lower() == last_hash:
                        print(f"✅ Se reanudará la consulta después de la línea {i+1}.")
                        return last_hash, current_exe_count
            print("⚠️ ¡ADVERTENCIA! El último hash procesado no se encontró en el archivo maestro.")
            return None, 0 
    except Exception as e:
        print(f"❌ Error al intentar determinar el punto de reanudación: {e}. Empezando desde el inicio.")
        return None, 0

def consultar_y_obtener_datos(hash_value: str) -> dict | None:
    """Consulta la API y devuelve un dict con 'hash', 'signature' y 'tags' si es 'exe'."""
    if not API_KEY:
        print("❌ Error: La clave API no se ha cargada.")
        return None
    payload = {'query': 'get_info', 'hash': hash_value}
    headers = {"Auth-Key": API_KEY}
    try:
        response = requests.post(MB_API_URL, data=payload, headers=headers, timeout=30)
        response.raise_for_status() 
        data = response.json()
        status = data.get('query_status')
        if status == 'ok' and data.get('data'):
            try:
                sample_data = data['data'][0]
                tags = sample_data.get('tags', [])
                if TARGET_TAG.lower() in [tag.lower() for tag in tags]:
                    return {
                        'hash': hash_value,
                        'signature': sample_data.get('signature', 'N/A'),
                        'tags': ','.join(tags) 
                    }
            except IndexError:
                print(f"⚠️ Respueta inesperada para {hash_value}: 'data' vacía.")
                return None
            except Exception as e:
                print(f"❌ Error al procesar JSON para {hash_value}: {e}")
                return None
        elif status == 'api_key_invalid':
            print("\n❌ ¡ERROR CRÍTICO! La clave API es inválida. Deteniendo la ejecución.")
            raise ValueError("API Key Inválida")
        return None
    except requests.exceptions.RequestException as e:
        print(f"\n❌ ERROR DE API/CONEXIÓN para {hash_value}: {e}. Retraso de 5s.")
        time.sleep(5)
        return None

def filtrar_hashes_con_reanudacion():
    """Ejecuta el filtrado y devuelve el estado de finalización y el conteo."""
    if not os.path.exists(MASTER_HASH_FILE):
        print(f"❌ Error: Archivo maestro no encontrado: {os.path.basename(MASTER_HASH_FILE)}. Ejecute la descarga primero.")
        return False, 0
    
    last_processed_hash, current_exe_count = obtener_punto_de_reanudacion(MASTER_HASH_FILE, OUTPUT_EXE_FILE)
    
    write_mode = 'a'
    start_processing = False if last_processed_hash else True
    
    print(f"\n✨ Iniciando filtrado de hashes. Muestras EXE objetivo: {TARGET_EXE_COUNT}")
    print(f"    (Total actual: {current_exe_count} / {TARGET_EXE_COUNT})")

    finished_all_hashes = True
    total_hashes_processed = 0
    
    try:
        is_new_file = not os.path.exists(OUTPUT_EXE_FILE) or current_exe_count == 0
        with open(OUTPUT_EXE_FILE, write_mode, newline='', encoding='utf-8') as csvfile:
            
            fieldnames = ['hash', 'signature', 'tags']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
            
            if is_new_file:
                writer.writeheader() 

            with open(MASTER_HASH_FILE, 'r', encoding='utf-8') as infile:
                for line in infile:
                    
                    if global_state['interrupted']: # Detener si Ctrl+C fue presionado
                        break
                        
                    if current_exe_count >= TARGET_EXE_COUNT:
                        print(f"\n🛑 Límite alcanzado ({TARGET_EXE_COUNT} EXE). Deteniendo el proceso de filtrado.")
                        finished_all_hashes = True
                        break
                        
                    hash_value = line.strip().lower()
                    
                    if hash_value and len(hash_value) == 64:
                        
                        if not start_processing and hash_value == last_processed_hash:
                            start_processing = True
                            continue 
                        
                        if not start_processing:
                            continue 

                        total_hashes_processed += 1
                        
                        sample_data = consultar_y_obtener_datos(hash_value)
                        
                        if sample_data:
                            writer.writerow(sample_data)
                            current_exe_count += 1
                            print(f"✅ Encontrado (EXE): {hash_value} | Total: {current_exe_count}")
                        else:
                            print(f"➡️ Analizado: {hash_value} (No EXE)")
                            
                        time.sleep(REQUEST_DELAY)
                
                else: 
                    finished_all_hashes = True

        return finished_all_hashes, current_exe_count

    except Exception:
        return False, current_exe_count

# ------------------------------------------------------------------------------

# --- 5. EJECUCIÓN PRINCIPAL (Con manejo de interrupción) ---

def handler(signum, frame):
    """Maneja la señal de interrupción (Ctrl+C)."""
    global_state['interrupted'] = True
    print("\n\n🚨 ¡Interrupción detectada (Ctrl+C)! Se detendrá el bucle para guardar progreso...")

# Configuración del manejador de señales
signal.signal(signal.SIGINT, handler)

if __name__ == "__main__":
    
    finished_state = False
    final_count = 0
    
    # 0. Asegura que exista la carpeta 'Scrap/ficheros'
    if not os.path.exists(os.path.dirname(OUTPUT_DIR)):
         os.makedirs(os.path.dirname(OUTPUT_DIR))
         
    try:
        # PASO 1: Descarga y Concatenación
        if not os.path.exists(MASTER_HASH_FILE):
            print("\n--- PASO 1: DESCARGA Y CONCATENACIÓN ---")
            archivos_descargados = descargar_archivos_de_github(GITHUB_API_URL, DOWNLOAD_DIR)
            concatenar_y_limpiar_archivos(archivos_descargados, MASTER_HASH_FILE, DOWNLOAD_DIR)
        else:
            print("\n--- PASO 1: SALTAR ---")
            print(f"Archivo maestro {os.path.basename(MASTER_HASH_FILE)} ya existe. Saltando descarga y concatenación.")

        # PASO 2: Filtrado y Reanudación
        print("\n--- PASO 2: FILTRADO CON REANUDACIÓN Y LÍMITE ---")
        finished_state, final_count = filtrar_hashes_con_reanudacion()
        global_state['count'] = final_count 

    except Exception as e:
        print(f"\n❌ ERROR CRÍTICO en la fase de inicialización o filtrado: {e}")
        
    finally:
        # El bloque FINALLY garantiza que el commit y push se ejecuten SIEMPRE
        # (alcanzado el límite, Ctrl+C, o cualquier excepción no capturada).
        
        # Usamos el conteo que obtuvimos al salir del bucle.
        current_count = final_count 
        
        # Si hubo una interrupción, el conteo podría no haberse actualizado si el error
        # ocurrió muy temprano. Usamos el conteo del estado global si es más alto.
        if global_state['interrupted']:
            current_count = global_state['count'] 

        if current_count > 0 or os.path.exists(OUTPUT_EXE_FILE):
             manejar_limpieza_y_push(finished_state, current_count)
        else:
             print("\n⚠️ No se ha realizado ningún progreso guardable. Finalizando.")
        
        sys.exit(0)