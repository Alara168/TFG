import os
import pyzipper 
import sys # Añadimos sys para un mejor manejo de errores

# --- CONFIGURACIÓN ---
# Nombre del archivo ZIP descargado 
ZIP_FILENAME = "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d.zip"

# Contraseña y cifrado
PASSWORD = b"infected" # Debe estar en formato bytes
EXTRACTION_DIR = "extracted_samples"


def extraer_archivo_malware(zip_path: str, output_dir: str, password: bytes):
    """
    Descomprime un archivo ZIP con cifrado AES (como AES128) usando pyzipper.
    """
    if not os.path.exists(zip_path):
        print(f"❌ Error: Archivo ZIP no encontrado en la ruta: {zip_path}")
        return

    # Crear el directorio de extracción si no existe
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"📁 Creado directorio de extracción: {output_dir}")

    print(f"🔓 Intentando extraer el archivo (con soporte AES): {zip_path}...")
    
    try:
        # pyzipper.AESZipFile es clave para manejar el cifrado AES128/256
        with pyzipper.AESZipFile(zip_path, 'r') as zf:
            
            # Establecer la contraseña 
            zf.setpassword(password)
            
            # Extraer todos los archivos
            zf.extractall(output_dir)
            
            extracted_files = zf.namelist()
            
            print(f"✅ Extracción exitosa. {len(extracted_files)} archivo(s) extraído(s) en: {output_dir}")
            print(f"Contenido extraído: {', '.join(extracted_files)}")

    except RuntimeError as e:
        # Captura errores como contraseña incorrecta
        print(f"❌ Error de Extracción (Runtime): {e}")
        print(f"Asegúrate de que la contraseña sea '{password.decode()}'")
    except pyzipper.BadZipFile:
        print(f"❌ Error: El archivo ZIP parece corrupto o no es un archivo ZIP válido.")
    except Exception as e:
        print(f"❌ Ocurrió un error inesperado durante la extracción: {e}")
        print(f"Detalle: {e}")


if __name__ == "__main__":
    # ⚠️ Recordatorio: Ejecutar esta operación solo en tu VM o entorno de sandbox.
    extraer_archivo_malware(ZIP_FILENAME, EXTRACTION_DIR, PASSWORD)