import pandas as pd

# 1. Cargar el dataset
# Nota: Asegúrate de que la ruta sea correcta según tu sistema de archivos
file_path = 'Scrap/dataset_mil_features_pure.csv'

try:
    df = pd.read_csv(file_path)
    print(f"Dataset cargado con éxito. Filas: {df.shape[0]}, Columnas: {df.shape[1]}")
    
    # --- ANÁLISIS DE COLUMNA 'entropy' ---
    if 'entropy' in df.columns:
        # Contamos cuántos valores no son exactamente 0
        non_zero_entropy = (df['entropy'] != 0).sum()
        print(f"\nValores distintos de 0 en 'entropy': {non_zero_entropy}")
    else:
        print("\nLa columna 'entropy' no existe en el dataset.")

    # --- ANÁLISIS DE COLUMNAS 'has_api' ---
    # Filtramos las columnas que empiezan con el prefijo indicado
    api_columns = [col for col in df.columns if col.startswith('has_api')]
    
    if api_columns:
        print(f"\nConteo de valores distintos de 0 en columnas 'has_api' ({len(api_columns)} encontradas):")
        
        # Creamos un diccionario o serie para mostrar los resultados de forma limpia
        api_results = {}
        for col in api_columns:
            non_zero_count = (df[col] != 0).sum()
            api_results[col] = non_zero_count
            
        # Convertimos a Serie para una visualización más ordenada
        print(pd.Series(api_results))
    else:
        print("\nNo se encontraron columnas que comiencen con 'has_api'.")

except FileNotFoundError:
    print(f"Error: No se encontró el archivo en la ruta {file_path}")
except Exception as e:
    print(f"Ocurrió un error inesperado: {e}")