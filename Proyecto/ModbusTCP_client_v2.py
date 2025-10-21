# ModbusTCP_Client_v2.py

#!pip install pymodbus==3.0.2
import time, random
from pymodbus.client import ModbusTcpClient as ModbusClient
from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadBuilder
from pymodbus.payload import BinaryPayloadDecoder

# Discrete Memoryless Source
def generate_random_values():
    """Funcion para generar valores aleatorios
       binarios (0 o 1) de un proceso industrial"""
    return [random.randint(0, 1) for i in range(5)]    # 5 bobinas

try:
    print('Start Modbus TCP Client', end = '\n\n')
    client = ModbusClient(host='192.168.0.84', port=1502)
    

    if not client.connect():
        print("Connection failed!")
        exit()
    else:
        print("Connected successfully.")
    
    m=1

    while True:
        print('N: ',m)
        
        time.sleep(1.0)
        
        # generar 5 valores aleatorios (0 o 1) para escribir en las bobinas
        data = generate_random_values()
        print('Write Coils',data)
        
        # escribir multiples bobinas (FC 0x0F)
        address = 0
        result  = client.write_coils(address, data)
       
        # leer las mismas bobinas (FC 0x01) para verificar la escritura 
        rd = client.read_coils(address, len(data))
        
        if rd.isError():
            print("Error al leer bobinas:", rd)
        else:
            print('Read Coils:',rd.bits[:len(data)], end = '\n\n')

        m += 1
        
        time.sleep(4.0)
        
except pymodbus.exceptions.ConnectionException as e:
    print("Modbus connection error", e)

# detectar otros errores inesperados
except Exception as e:  
    print("Error:",e)

finally:
    print("Modbus TCP client stopped")
    client.close()
