import os
import requests
import json
from dotenv import load_dotenv

# --- 1. CONFIGURACIÓN ---
load_dotenv()
API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")

API_URL = "https://mb-api.abuse.ch/api/v1/"
TARGET_SHA256 = "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"
OUTPUT_FILENAME = f"{TARGET_SHA256}.zip"

PAYLOAD = {
    'query': 'get_file',
    'sha256_hash': TARGET_SHA256
}

HEADERS = {
    "Auth-Key": API_KEY 
}


def descargar_sample_por_header(sha256_hash: str):
    if not API_KEY:
        print("❌ Error: La clave API (MALWAREBAZAAR_API_KEY) no se pudo cargar.")
        return
    
    # IMPORTANTE: No imprimir la clave aquí ni en global.
    print(f"🚀 Intentando descargar sample con hash: {sha256_hash}...")
    
    try:
        response = requests.post(API_URL, data=PAYLOAD, headers=HEADERS, timeout=120)
        response.raise_for_status() # Maneja 4xx y 5xx

        # Intenta decodificar la respuesta como JSON primero.
        # Si tiene éxito, significa que NO es el archivo binario, sino un mensaje de error.
        try:
            error_data = response.json()
            status = error_data.get('query_status', 'unknown_error')
            
            # Si el JSON es 'ok', pero no devolvió el archivo, algo raro pasa,
            # pero generalmente el status será de error.
            if status == 'file_not_found':
                 print(f"❌ Error de la API: Hash no encontrado para descarga.")
            elif status == 'api_key_invalid':
                 print(f"❌ Error de la API: La clave enviada es inválida.")
            else:
                 print(f"❌ Error de la API (JSON): {status}")
            return

        except json.JSONDecodeError:
            # ¡ÉXITO! Si falla la decodificación JSON, significa que la respuesta
            # no era JSON, sino el archivo ZIP binario esperado.
            
            with open(OUTPUT_FILENAME, 'wb') as f:
                f.write(response.content)

            print(f"✅ Descarga completa. Muestra guardada como: {OUTPUT_FILENAME}")
            print("⚠️ Recordatorio: El archivo ZIP está **cifrado** con la contraseña: **infected**")
            return

    except requests.exceptions.HTTPError as e:
        # Esto captura errores como 403 Forbidden (clave inválida)
        print(f"❌ Error HTTP: {e}")
        print("🔥 Si ves 403, revisa tu clave 'Auth-Key' o contacta al soporte de la API.")
    except requests.exceptions.RequestException as e:
        print(f"❌ Ocurrió un error en la solicitud (conexión o timeout): {e}")


if __name__ == "__main__":
    descargar_sample_por_header(TARGET_SHA256)