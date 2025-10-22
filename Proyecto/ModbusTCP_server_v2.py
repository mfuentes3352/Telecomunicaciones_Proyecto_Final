# -*- coding: utf-8 -*-
"""
Created on Sat Aug  2 01:18:22 2025

@author: Martin
"""

# ModbusTCP_server_v2.py
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
