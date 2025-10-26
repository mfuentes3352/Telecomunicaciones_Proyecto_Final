# -*- coding: utf-8 -*- 
"""
Created on Thu Oct 16 17:04:45 2025

@author: Martin
"""

import pandas as pd

def procesar_csv(nombre_archivo, columna_tiempo, formato_salida='texto'):
    """
    Procesa un CSV reemplazando ',' por '.' en la columna de tiempo sin modificar la fecha.
    
    Args:
        nombre_archivo (str): Ruta del archivo CSV.
        columna_tiempo (str): Nombre de la columna que contiene el tiempo.
        formato_salida (str): 'texto' (mantiene todo igual, solo cambia coma por punto)
                              'float' (convierte a número si solo es tiempo)
    
    Returns:
        pd.DataFrame: DataFrame procesado.
    """
    # Leer el CSV
    df = pd.read_csv(nombre_archivo)
    
    # Asegurar que la columna sea texto
    df[columna_tiempo] = df[columna_tiempo].astype(str)
    
    # Reemplazar ',' por '.' solo en la parte de la hora 
    df[columna_tiempo] = df[columna_tiempo].str.replace(',', '.', regex=False)
    
    # Si el usuario quiere convertir a float 
    if formato_salida == 'float':
        try:
            df[columna_tiempo] = df[columna_tiempo].astype(float)
        except ValueError:
            print("No se puede convertir a float porque la columna contiene fechas.")
    
    return df


# Uso del programa
archivo = r"C:\Users\Martin\Desktop\sniffer\Mediciones\RTT_Wireshark_21_10_25_sesion2.csv"
columna = 'Time'

df_procesado = procesar_csv(archivo, columna, formato_salida='texto')

# Guardar el CSV procesado
df_procesado.to_csv(
    r"C:\Users\Martin\Desktop\sniffer\Mediciones\RTT_Wireshark_21_10_25_sesion2_procesado.csv",
    index=False,
    encoding='utf-8'
)

