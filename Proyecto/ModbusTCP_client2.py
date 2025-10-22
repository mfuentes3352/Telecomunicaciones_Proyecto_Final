# ModbusTCP_Client.py

#!pip install pymodbus==3.0.2
import time, random
from pymodbus.client import ModbusTcpClient as ModbusClient
from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadBuilder
from pymodbus.payload import BinaryPayloadDecoder

# Discrete Memoryless Source (unidades: celsius, bar, rpm, Hz, MW)
def generate_random_values():
    """Funcion para generar valores aleatorios de un proceso industrial"""
    steam_temperature_boiler_output = random.randint(530, 540)
    steam_pressure_boiler_output = random.randint(180, 200)
    angular_velocity_turbine = random.randint(2950, 3050)
    frequency_i_ac = random.randint(48, 52)
    power_generated = random.randint(160, 200)

    data = [steam_temperature_boiler_output,
            steam_pressure_boiler_output,
            angular_velocity_turbine,
            frequency_i_ac,
            power_generated]
    
    return data

try:
    print('Start Modbus TCP Client', end = '\n\n')
    client = ModbusClient(host='192.168.0.76', port=1502)
    #client = ModbusClient(host='192.168.0.84', port=1502)

    if not client.connect():
        print("Connection failed!")
        exit()
    else:
        print("Connected successfully.")
    
    reg=0
    address=0
    m=1

    # initialize data
    data = [540,200,3000,50,200]
    
    # Run the client indefinitely

    while True:
        print('N: ',m)
        
        time.sleep(1.0)
        
        # update the values of the variables
        data = generate_random_values()

        # write holding registers (40001 to 40005) 
        print('Write',data)
        
        builder = BinaryPayloadBuilder(byteorder=Endian.Big,\
                                       wordorder=Endian.Little)
        
        for d in data:
           builder.add_16bit_int(int(d))
        
        payload = builder.build()
        
        # Configuración de registros de prueba
        result  = client.write_registers(int(reg), payload,\
                                        skip_encode=True, unit=int(address))
       
        # read holding registers 
        rd = client.read_holding_registers(reg, len(data)).registers
        print('Read',rd, end = '\n\n')

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
