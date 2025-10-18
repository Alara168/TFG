import os
import requests
import json
import time
import csv
from dotenv import load_dotenv

# ==============================================================================
#                      DESCRIPCIÓN DEL FLUJO DE TRABAJO (TFG)
# ==============================================================================
"""
Este script realiza el proceso completo de recolección y filtrado de hashes de malware
para el TFG, garantizando la reanudación ante interrupciones y la limitación de muestras.

Pasos ejecutados:
1.  CONFIGURACIÓN: Carga la clave API de MalwareBazaar desde el archivo .env.
2.  DESCARGA DE HASHES (GitHub): Descarga todos los archivos .txt de la carpeta SHA256 
    del repositorio de GitHub en un directorio temporal (github_hashes_temp).
3.  CONCATENACIÓN Y LIMPIEZA INICIAL: Combina todos los hashes únicos en un único archivo 
    maestro (MASTER_SHA256_LIST.txt) dentro de la carpeta Scrap/ficheros.
    Luego, borra los archivos temporales de GitHub y la carpeta temporal.
4.  FILTRADO (MalwareBazaar API):
    a. Consulta la API de MalwareBazaar con 'get_info' para cada hash.
    b. Limita la recolección a un objetivo de 40,000 hashes con la etiqueta "exe".
    c. Guarda los resultados en un archivo CSV (hashes_exe.csv) separado por ';', 
       registrando el HASH, la SIGNATURE y los TAGS.
    d. Implementa una pausa optimizada de 0.5 segundos entre solicitudes.
    e. Incluye manejo de errores para evitar que la ejecución se detenga por respuestas malformadas.
5.  REANUDACIÓN: Si el script falla o se interrumpe, detecta el último hash escrito en 
    hashes_exe.csv y continúa el proceso desde ese punto en el archivo maestro.
6.  LIMPIEZA FINAL: Una vez que el filtrado finaliza o alcanza el límite, el archivo 
    maestro MASTER_SHA256_LIST.txt es borrado.

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
REQUEST_DELAY = 0.2
TARGET_EXE_COUNT = 40000 

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

# --- 3. FUNCIONES DE FILTRADO Y REANUDACIÓN ---

def obtener_punto_de_reanudacion(master_file: str, output_file: str) -> tuple[str | None, int]:
    """
    Determina el último hash procesado y el número de muestras EXE ya recolectadas 
    leyendo el CSV de salida.
    """
    if not os.path.exists(output_file):
        return None, 0

    try:
        current_exe_count = 0
        last_hash = None
        
        with open(output_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f, delimiter=';')
            try:
                header = next(reader) # Saltar la cabecera
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
    """
    Consulta la API y devuelve un dict con 'hash', 'signature' y 'tags' si es 'exe'.
    Añadido manejo de excepciones JSON interno para mitigar el error 'NoneType'.
    """
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
                # Bloque try-except para proteger contra JSON malformado o inesperado
                sample_data = data['data'][0]
                tags = sample_data.get('tags', [])
                
                if TARGET_TAG.lower() in [tag.lower() for tag in tags]:
                    return {
                        'hash': hash_value,
                        'signature': sample_data.get('signature', 'N/A'),
                        'tags': ','.join(tags) 
                    }
            except IndexError:
                # Ocurre si 'data' está presente pero es una lista vacía
                print(f"⚠️ Respueta inesperada para {hash_value}: 'data' vacía.")
                return None
            except Exception as e:
                print(f"❌ Error al procesar JSON para {hash_value}: {e}")
                return None
            
        elif status == 'api_key_invalid':
            print("\n❌ ¡ERROR CRÍTICO! La clave API es inválida. Deteniendo la ejecución.")
            exit()
            
        return None

    except requests.exceptions.RequestException as e:
        print(f"\n❌ ERROR DE API/CONEXIÓN para {hash_value}: {e}. Retraso de 5s.")
        time.sleep(5)
        return None

def filtrar_hashes_con_reanudacion():
    """Ejecuta el filtrado con la lógica de reanudación, limitación y limpieza final."""
    if not os.path.exists(MASTER_HASH_FILE):
        print(f"❌ Error: Archivo maestro no encontrado: {os.path.basename(MASTER_HASH_FILE)}. Ejecute la descarga primero.")
        return
    
    if not API_KEY:
        print("❌ Error: La clave API no se ha cargado. Revisa tu .env.")
        return

    # Determinar reanudación y conteo inicial
    last_processed_hash, current_exe_count = obtener_punto_de_reanudacion(MASTER_HASH_FILE, OUTPUT_EXE_FILE)
    
    write_mode = 'a'
    start_processing = False if last_processed_hash else True
    
    print(f"\n✨ Iniciando filtrado de hashes. Muestras EXE objetivo: {TARGET_EXE_COUNT}")
    print(f"    (Total actual: {current_exe_count} / {TARGET_EXE_COUNT})")

    finished_all_hashes = True
    total_hashes_processed = 0
    
    # INICIO DEL PROCESO DE FILTRADO
    try:
        # Abrir el CSV.
        is_new_file = not os.path.exists(OUTPUT_EXE_FILE) or current_exe_count == 0
        with open(OUTPUT_EXE_FILE, write_mode, newline='', encoding='utf-8') as csvfile:
            
            fieldnames = ['hash', 'signature', 'tags']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
            
            if is_new_file:
                writer.writeheader() 

            with open(MASTER_HASH_FILE, 'r', encoding='utf-8') as infile:
                for line in infile:
                    
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


    except requests.exceptions.RequestException as e:
        finished_all_hashes = False
        print(f"\n❌ ERROR DE API/CONEXIÓN: {e}. Guardando progreso y deteniendo...")
        print("🔥 Vuelva a ejecutar el script para reanudar.")
        return 
    except Exception as e:
        finished_all_hashes = False
        print(f"\n❌ Ocurrió un error inesperado: {e}")
        return
    
    # CÁLCULOS FINALES Y LIMPIEZA
    print(f"\n--- Resumen Final ---")
    print(f"Total de hashes consultados en esta sesión: {total_hashes_processed}")
    print(f"Total de hashes EXE en {os.path.basename(OUTPUT_EXE_FILE)}: {current_exe_count}")

    # BORRADO DEL FICHERO MAESTRO
    if finished_all_hashes:
        print(f"\n🗑️ Proceso de filtrado completado. Borrando fichero maestro: {os.path.basename(MASTER_HASH_FILE)}")
        try:
            os.remove(MASTER_HASH_FILE)
            print("✅ Fichero maestro borrado correctamente.")
        except Exception as e:
            print(f"❌ No se pudo borrar el fichero maestro: {e}")


# --- 4. EJECUCIÓN PRINCIPAL ---

if __name__ == "__main__":
    
    # Asegura que exista la carpeta 'Scrap/ficheros'
    if not os.path.exists(os.path.dirname(OUTPUT_DIR)):
         os.makedirs(os.path.dirname(OUTPUT_DIR))
    
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
    filtrar_hashes_con_reanudacion()