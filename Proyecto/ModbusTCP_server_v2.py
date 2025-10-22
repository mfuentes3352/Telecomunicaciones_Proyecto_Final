# -*- coding: utf-8 -*-
"""
Created on Sat Aug  2 01:18:22 2025

@author: Martin

# ModbusTCP_server_v2.py

Inicializa un servidor Modbus TCP en el host local (IP 192.168.0.82/24) que escucha en el puerto 1502.
Define la memoria de aplicación del dispositivo con cuatro bloques consecutivos de 9999 registros cada uno,
asignados respectivamente a entradas discretas, bobinas, registros de entrada y registros de retención.

Cada solicitud recibida activa una operación local de lectura o escritura en la memoria del servidor,
y genera una respuesta Modbus (o una excepción, según corresponda) que se envía al cliente.

El servidor monitorea los cambios en los registros de retención (holding registers) e imprime por consola
los nuevos valores cuando detecta modificaciones.
"""


from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock

class CustomDataBlock(ModbusSequentialDataBlock):
    def setValues(self, address, values):
        old_values = self.getValues(address, len(values))
        super().setValues(address, values)

        # Si algún valor cambió, mostramos los primeros 5 registros de retención
        if any(old != new for old, new in zip(old_values, values)):
            first_five = self.getValues(0, 5)
            print(f"[INFO] Cambio detectado - HR[0:4] = {first_five}")

def run_async_server():
    nreg = 9999
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*nreg),
        co=ModbusSequentialDataBlock(0, [0]*nreg),
        hr=CustomDataBlock(0, [0]*nreg),  # Usamos la clase modificada
        ir=ModbusSequentialDataBlock(0, [0]*nreg)
    )
    context = ModbusServerContext(slaves=store, single=True)

    identity = ModbusDeviceIdentification()
    identity.VendorName = 'mf_ni_CpI'
    identity.ProductCode = 'mf_ni_CpI'
    identity.VendorUrl = 'https://mf_ni_CpI.com'
    identity.ProductName = 'Modbus Server'
    identity.ModelName = 'Modbus Server'
    identity.MajorMinorRevision = '3.0.2'

    StartTcpServer(context=context, host='0.0.0.0',
                   identity=identity, address=("192.168.0.77", 1502))

if __name__ == "__main__":
    print('Modbus server started on 192.168.0.77 port 1502')
    run_async_server()
