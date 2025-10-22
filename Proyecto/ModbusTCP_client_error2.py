# -*- coding: utf-8 -*-
"""
Created on Tue Jul 29 17:42:22 2025

@author: Martin

Escribe 5 bobinas (FC 0x0F).

En cada iteración, usa una dirección válida o inválida (por ejemplo, -1 o 12000) 
con una probabilidad del 20% de error.

Muestra por consola qué dirección se está utilizando, junto con los valores 
de las bobinas.
"""

import time, random
from pymodbus.client import ModbusTcpClient as ModbusClient
from pymodbus.exceptions import ModbusIOException

# Genera 5 valores binarios (0 o 1)
def generate_random_values():
    return [random.randint(0, 1) for _ in range(5)]

# Decide la dirección de inicio (válida o inválida con 20% de probabilidad) 0.95 en la prueba de errores
def generate_random_address():
    if random.random() < 0.95:
        # Dirección fuera de rango
        return random.choice([10000, 12000, 20000, 24000, 65535])
    else:
        # Dirección válida: 0 a 9994 (para 5 bobinas)
        return random.randint(0, 9994)

try:
    print('Start Modbus TCP Client\n')
    client = ModbusClient(host='192.168.0.77', port=1502) #192.168.0.84

    if not client.connect():
        print("Connection failed!")
        exit()
    else:
        print("Connected successfully.")
    
    m = 1

    while True:
        print(f'N: {m}')
        time.sleep(1.0)

        data = generate_random_values()
        address = generate_random_address()

        print(f'Write Coils: {data} en la dirección: {address}')

        try:
            # FC 0x0F: escribir múltiples bobinas
            result = client.write_coils(address, data)
            
            if result.isError():
                print("❌ Error al escribir bobinas:", result)
            else:
                print("✅ Escritura exitosa.")

            # Intentar leer las mismas bobinas para ver si se escribió
            rd = client.read_coils(address, len(data))
            if rd.isError():
                print("❌ Error al leer bobinas:", rd)
            else:
                print(f'Read Coils: {rd.bits[:len(data)]}\n')

        except Exception as e:
            print("⚠️ Excepción inesperada:", e)

        m += 1
        time.sleep(4.0)

except Exception as e:
    print("💥 Error general:", e)

finally:
    print("Modbus TCP client stopped")
    client.close()
