import os
import requests
import json
import csv
import time
import threading
import zipfile
import io
import subprocess 
from datetime import date
from dotenv import load_dotenv
import sys
import signal

# --- 1. CONFIGURACIÓN Y CONSTANTES ---
load_dotenv()
API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")

# Contraseña estándar de MalwareBazaar para ZIPs cifrados
ZIP_PASSWORD = b"infected" 

# Rutas y URLs
API_URL = "https://mb-api.abuse.ch/api/v1/"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "ficheros")

# Archivos de entrada/salida/estado
HASHES_INPUT_FILE = os.path.join(OUTPUT_DIR, "hashes_exe.csv") 
DOWNLOAD_LOG_FILE = os.path.join(OUTPUT_DIR, "processed_downloads.txt")
DAILY_STATUS_FILE = os.path.join(OUTPUT_DIR, "daily_status.json")
SAMPLES_DIR = os.path.join(OUTPUT_DIR, "muestras") 

# Límite diario de descargas
DAILY_DOWNLOAD_LIMIT = 2000 
REQUEST_DELAY = 1.5 
MAX_THREADS = 10 

# Variables de estado global
global_state = {'interrupted': False, 'count': 0}

# Asegurar la existencia de directorios
os.makedirs(SAMPLES_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ------------------------------------------------------------------------------

# --- 2. FUNCIONES AUXILIARES DE GIT ---

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
        if "nothing to commit" in resultado.stdout.lower():
            return False 
            
        print(f"✅ Git OK: {comando[1]} | {resultado.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Git ERROR al ejecutar '{' '.join(comando)}':")
        print(f"   Stderr: {e.stderr.strip()}")
        return False
    except FileNotFoundError:
        print("❌ Error: Git no se encontró. Asegúrate de que esté instalado y en PATH.")
        return False

def manejar_limpieza_y_push(current_download_count: int):
    """
    Realiza el commit y push de todos los archivos modificados (logs, status, muestras).
    """
    root_dir = os.path.dirname(BASE_DIR) 
    total_samples = len([name for name in os.listdir(SAMPLES_DIR) if name.endswith('.bin')])

    print("\n--- 7. COMMIT Y PUSH AUTOMÁTICO DE DESCARGAS ---")
    
    # 1. Añadir TODOS los archivos modificados/creados ('git add .')
    print("➕ Añadiendo todos los archivos modificados (logs, status, muestras) al staging...")
    ejecutar_comando_git(["git", "add", "."], root_dir)
    
    # 2. Crear mensaje de commit
    commit_msg = f"DESCARGAS: {current_download_count} muestras descargadas hoy. Total: {total_samples}."
    if current_download_count >= DAILY_DOWNLOAD_LIMIT:
         commit_msg = f"DESCARGAS: Límite diario de {DAILY_DOWNLOAD_LIMIT} muestras alcanzado. Total: {total_samples}."
    
    # 3. Crear el Commit
    if ejecutar_comando_git(["git", "commit", "-m", commit_msg], root_dir):
        # 4. Hacer Push a GitHub (Solo si el commit fue exitoso)
        print("\n📤 Intentando hacer push a GitHub...")
        ejecutar_comando_git(["git", "push", "origin", "main"], root_dir)
    else:
        print("⚠️ No hay cambios detectados para hacer commit/push. Progreso guardado localmente.")

# ------------------------------------------------------------------------------

# --- 3. FUNCIONES DE ESTADO Y LOGS ---

def load_daily_status() -> dict:
    """Carga el estado de descargas diarias y aplica la lógica de reinicio."""
    today = date.today().isoformat()
    default_status = {'last_run_date': today, 'daily_count': 0}
    
    if not os.path.exists(DAILY_STATUS_FILE):
        return default_status

    try:
        with open(DAILY_STATUS_FILE, 'r') as f:
            status = json.load(f)
            last_run_date = status.get('last_run_date')
            daily_count = status.get('daily_count', 0)
            
            if last_run_date != today:
                print(f"📅 ¡Nuevo día detectado! Contador diario reiniciado.")
                return default_status
            else:
                print(f"⏳ Continuación: {daily_count} muestras descargadas hoy. Restantes: {DAILY_DOWNLOAD_LIMIT - daily_count}")
                return status
                
    except Exception:
        print(f"❌ Error al cargar/procesar el estado diario. Reiniciando el contador.")
        return default_status

def save_daily_status(status: dict):
    """Guarda el estado actual del conteo diario."""
    status['last_run_date'] = date.today().isoformat()
    try:
        with open(DAILY_STATUS_FILE, 'w') as f:
            json.dump(status, f, indent=4)
    except Exception as e:
        print(f"❌ Error al guardar el estado diario: {e}")

def load_processed_hashes() -> set:
    """Carga el set de hashes que ya han sido procesados (descargados/intentados)."""
    if not os.path.exists(DOWNLOAD_LOG_FILE):
        return set()
    
    try:
        with open(DOWNLOAD_LOG_FILE, 'r') as f:
            return set(line.strip().lower() for line in f if line.strip())
    except Exception:
        return set()

def log_processed_hash(hash_value: str):
    """Añade un hash al archivo de log para la persistencia entre sesiones."""
    try:
        with open(DOWNLOAD_LOG_FILE, 'a') as f:
            f.write(hash_value.lower() + '\n')
    except Exception:
        pass

# ------------------------------------------------------------------------------

# --- 4. FUNCIONES DE CONCURRENCIA Y DESCOMPRESIÓN ---

def unzip_sample(zip_data: bytes, sha256_hash: str, output_path: str, thread_limiter: threading.Semaphore):
    """
    Función objetivo del hilo: descomprime el ZIP cifrado en memoria 
    y solo guarda el fichero final renombrado.
    """
    try:
        zip_buffer = io.BytesIO(zip_data)
        
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            member_name = zf.namelist()[0] 
            final_file_name = f"{sha256_hash}.bin"
            final_file_path = os.path.join(output_path, final_file_name)

            file_content = zf.read(member_name, pwd=ZIP_PASSWORD)
            
            with open(final_file_path, 'wb') as f:
                f.write(file_content)
            
            print(f"✅ [Hilo {threading.get_ident()}] Muestra descomprimida y guardada: {final_file_name}")

    except zipfile.BadZipFile:
        print(f"❌ [Hilo {threading.get_ident()}] Error de ZIP: El archivo {sha256_hash} está corrupto.")
    except Exception as e:
        print(f"❌ [Hilo {threading.get_ident()}] Error desconocido al descomprimir {sha256_hash}: {e}")
    finally:
        thread_limiter.release()

def download_sample_and_unzip(sha256_hash: str, thread_limiter: threading.Semaphore):
    """Descarga la muestra, lanza un hilo de descompresión."""
    
    payload = {'query': 'get_file', 'sha256_hash': sha256_hash}
    headers = {"Auth-Key": API_KEY}
    
    try:
        response = requests.post(API_URL, data=payload, headers=headers, timeout=120)
        
        # ************ SOLUCIÓN A 'Expecting value' ************
        # 1. Si la respuesta está vacía, es un error del servidor/clave.
        if not response.content:
            print(f"❌ Error API: Respuesta vacía o nula para {sha256_hash}. (Posible clave inválida o error 403 sin contenido).")
            return False

        response.raise_for_status() # Maneja 4xx y 5xx

        # 2. Intentar decodificar como JSON para buscar errores específicos (Ej: file_not_found)
        try:
            error_data = response.json()
            status = error_data.get('query_status', 'unknown_error')
            
            if status == 'file_not_found':
                print(f"❌ Error API: Hash no encontrado para descarga: {sha256_hash}")
            elif status == 'api_key_invalid':
                print(f"❌ ¡ERROR CRÍTICO! La clave enviada es inválida.")
                global_state['interrupted'] = True
            else:
                print(f"❌ Error API (JSON): {status} para {sha256_hash}")
            return False 

        except json.JSONDecodeError:
            # 3. ÉXITO: Si falla la decodificación, es porque tenemos el binario ZIP
            zip_data = response.content
            print(f"🚀 Descargado ZIP de {sha256_hash}. Tamaño: {len(zip_data)} bytes. Lanzando hilo...")
            
            # 4. Lanzar hilo de descompresión
            thread_limiter.acquire()
            thread = threading.Thread(target=unzip_sample, 
                                      args=(zip_data, sha256_hash, SAMPLES_DIR, thread_limiter))
            thread.start()
            
            return True

    except requests.exceptions.RequestException as e:
        print(f"❌ Error de solicitud para {sha256_hash}: {e}")
        return False
        
# ------------------------------------------------------------------------------

# --- 5. FUNCIÓN PRINCIPAL ---

def main_download_loop():
    """Bucle principal de descarga con límites y persistencia."""
    
    daily_status = load_daily_status()
    processed_hashes = load_processed_hashes()
    
    current_count = daily_status['daily_count']
    
    if current_count >= DAILY_DOWNLOAD_LIMIT:
        print(f"\n🛑 Límite de {DAILY_DOWNLOAD_LIMIT} muestras alcanzado para hoy.")
        return current_count

    hashes_to_process = []
    if not os.path.exists(HASHES_INPUT_FILE):
        print(f"❌ Error: Archivo de entrada no encontrado: {HASHES_INPUT_FILE}")
        return current_count

    try:
        with open(HASHES_INPUT_FILE, 'r', encoding='utf-8') as f:
            reader = csv.reader(f, delimiter=';')
            next(reader) 
            
            for row in reader:
                if row:
                    hash_value = row[0].strip().lower()
                    if hash_value not in processed_hashes:
                        hashes_to_process.append(hash_value)
    except Exception:
        return current_count

    print(f"Total de hashes (nuevos) para intentar descargar: {len(hashes_to_process)}")
    
    thread_limiter = threading.BoundedSemaphore(MAX_THREADS)
    
    for hash_value in hashes_to_process:
        
        if global_state['interrupted'] or current_count >= DAILY_DOWNLOAD_LIMIT:
            break
            
        print(f"\n[{current_count+1}/{DAILY_DOWNLOAD_LIMIT}] Procesando hash: {hash_value}")

        if download_sample_and_unzip(hash_value, thread_limiter):
            current_count += 1
            log_processed_hash(hash_value)
            daily_status['daily_count'] = current_count
            save_daily_status(daily_status)
            global_state['count'] = current_count # Actualizar estado global
            time.sleep(REQUEST_DELAY) 
        else:
            log_processed_hash(hash_value) 
            time.sleep(5) 
            
    # 4. Finalización (espera de hilos)
    print("⏳ Esperando a que terminen los hilos de descompresión activos...")
    for i in range(MAX_THREADS):
        thread_limiter.acquire()
    for i in range(MAX_THREADS):
        thread_limiter.release()
            
    print("✅ Proceso de descarga finalizado.")
    
    return current_count

# ------------------------------------------------------------------------------

# --- 6. MANEJO DE INTERRUPCIÓN Y EJECUCIÓN ---

def handler(signum, frame):
    """Maneja la señal de interrupción (Ctrl+C)."""
    global_state['interrupted'] = True
    print("\n\n🚨 ¡Interrupción detectada (Ctrl+C)! Se detendrá el bucle principal de descarga. Los hilos activos finalizarán.")

signal.signal(signal.SIGINT, handler)

if __name__ == "__main__":
    
    final_count = 0
    
    try:
        final_count = main_download_loop()

    except Exception as e:
        print(f"\n❌ ERROR CRÍTICO en la fase de descarga: {e}")
        
    finally:
        # El bloque FINALLY garantiza que el commit y push se ejecuten SIEMPRE.
        
        # Usamos el conteo final del día (no el total histórico) para el mensaje de commit.
        count_for_commit = global_state.get('count', 0)
        if count_for_commit == 0 and final_count > 0:
            count_for_commit = final_count
            
        if count_for_commit > 0 or os.path.exists(DOWNLOAD_LOG_FILE):
             manejar_limpieza_y_push(count_for_commit)
        else:
             print("\n⚠️ No se ha realizado ningún progreso guardable. Finalizando.")
        
        sys.exit(0)