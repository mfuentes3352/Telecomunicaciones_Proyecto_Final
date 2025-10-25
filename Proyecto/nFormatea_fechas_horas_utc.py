# -*- coding: utf-8 -*-
"""
Created on Thu Oct 16 17:04:45 2025

@author: Martin
"""

import pandas as pd

def procesar_csv(nombre_archivo, columna_tiempo, formato_salida='datetime'):
    """
    Procesa un CSV reemplazando ',' por '.' en la columna de tiempo y la convierte a datetime o float.
    
    Args:
        nombre_archivo (str): Ruta del archivo CSV.
        columna_tiempo (str): Nombre de la columna que contiene el tiempo.
        formato_salida (str): 'datetime' para convertir a datetime, 'float' para número.
    
    Returns:
        pd.DataFrame: DataFrame procesado.
    """
    # Leer el CSV
    df = pd.read_csv(nombre_archivo)
    
    # Reemplazar ',' por '.'
    df[columna_tiempo] = df[columna_tiempo].astype(str).str.replace(',', '.', regex=False)
    
    # Convertir al formato deseado
    if formato_salida == 'float':
        df[columna_tiempo] = df[columna_tiempo].astype(float)
    elif formato_salida == 'datetime':
        # Si tu columna tiene solo tiempo tipo 'HH:MM:SS,mmm', necesitamos agregar fecha si quieres restarlas con timestamps completos
        # Por ejemplo, puedes concatenar con una fecha base
        fecha_base = '2025-10-16 '  # Ajusta según necesites
        df[columna_tiempo] = pd.to_datetime(fecha_base + df[columna_tiempo])
        df[columna_tiempo] = df[columna_tiempo].dt.tz_localize(None)
    else:
        raise ValueError("formato_salida debe ser 'float' o 'datetime'")
    
    return df

# Uso del programa
archivo = r"C:\Users\Martin\Desktop\sniffer\Mediciones\RTT_Wireshark_21_10_25_sesion2.csv"
columna = 'Time'
df_procesado = procesar_csv(archivo, columna, formato_salida='datetime')

df_procesado.to_csv(r"C:\Users\Martin\Desktop\sniffer\Mediciones\RTT_Wireshark_21_10_25_sesion2_procesado.csv", index=False)
