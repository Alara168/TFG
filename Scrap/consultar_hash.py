import os
import requests
import json
from dotenv import load_dotenv

# --- 1. CONFIGURACIÓN ---
# Carga las variables de entorno desde el archivo .env
load_dotenv()
API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")

API_URL = "https://mb-api.abuse.ch/api/v1/"

# --- 2. DATOS DE LA CONSULTA ---
# Hash a consultar (puedes cambiarlo a MD5 o SHA1 si lo deseas)
TARGET_HASH = "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d" 

# Payload: Define la acción (get_info) y el hash a consultar
PAYLOAD = {
    'query': 'get_info',
    'hash': TARGET_HASH
}

# Headers: Incluye la clave de autenticación
HEADERS = {
    "Auth-Key": API_KEY 
}

def consultar_malware_hash(hash_value: str):
    """
    Consulta los metadatos de un hash específico en MalwareBazaar.
    """
    if not API_KEY:
        print("Error: La clave API (MALWAREBAZAAR_API_KEY) no se ha cargado. Revisa tu archivo .env.")
        return
    
    print(f"🔎 Consultando información para el hash: {hash_value}...")
    
    try:
        # Realiza la solicitud POST. Se envía el payload en 'data' y la clave en 'headers'.
        response = requests.post(API_URL, data=PAYLOAD, headers=HEADERS, timeout=30)
        response.raise_for_status()  # Lanza una excepción si hay un código de error HTTP (como 403)

        # La respuesta es JSON, lo decodificamos
        data = response.json()
        
        # Verificar el estado de la consulta
        status = data.get('query_status')
        print(f"Estado de la consulta: {status}\n")

        if status == 'ok':
            # Si el sample es conocido, devuelve la lista de resultados (generalmente un elemento)
            if data.get('data'):
                sample_data = data['data'][0]
                
                print("--- Metadatos del Sample ---")
                print(f"Filename: {sample_data.get('file_name')}")
                print(f"Signature: {sample_data.get('signature')}")
                print(f"Tags: {', '.join(sample_data.get('tags', []))}")
                print(f"Uploader: {sample_data.get('uploader')}")
                print(f"First Seen: {sample_data.get('first_seen')}")
                
                # Puedes guardar estos datos para tu TFG
                # print(json.dumps(sample_data, indent=4)) 
                
            else:
                print("Error: La respuesta es 'ok', pero no contiene datos del sample.")
                
        elif status == 'hash_not_found':
            print("El hash proporcionado no se encontró en la base de datos de MalwareBazaar.")
        
        elif status == 'api_key_invalid':
            print("Error de Autenticación: La clave 'Auth-Key' es inválida.")
        
        else:
            print(f"Estado desconocido de la API: {status}")


    except requests.exceptions.HTTPError as e:
        print(f"Error HTTP: {e}")
        print("Verifica tu clave API. Un 403 o 400 suele indicar un problema con la autenticación o el formato de la solicitud.")
    except requests.exceptions.RequestException as e:
        print(f"Error de conexión: {e}")
    except json.JSONDecodeError:
        print("Error: La respuesta de la API no es un JSON válido.")

if __name__ == "__main__":
    consultar_malware_hash(TARGET_HASH)