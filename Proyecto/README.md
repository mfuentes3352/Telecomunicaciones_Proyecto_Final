# Proyecto: Captura y análisis de tráfico Modbus TCP

En este directorio se encuentran los códigos desarrollados para el trabajo final de *Telecomunicaciones*, titulado *“Captura y análisis de tráfico en redes Modbus TCP para inspección de estado de red en tiempo real”*, realizado en el marco de la asignatura **Proyecto 2** de la carrera **Ingeniería Electrónica** de la **FCEIA – UNR**.

El repositorio incluye los **scripts de los Clientes y Servidores Modbus TCP**, junto con el **script de la Interfaz Gráfica de Usuario (GUI) del analizador de tráfico**.

Todos los scripts pueden ejecutarse en distintas máquinas virtuales conectadas en red. A continuación, se describen sus principales funcionalidades.


## ModbusTCP_Client.py

Este script inicializa un **cliente Modbus TCP** en el *host local*, estableciendo conexión con el **servidor Modbus TCP** (`192.168.0.77:1502`).  
Envía solicitudes de escritura y lectura de registros de manera continua, simulando un proceso industrial con cinco variables:

- Temperatura del vapor de caldera  
- Presión del vapor de caldera  
- Velocidad angular de la turbina  
- Frecuencia de la corriente eléctrica  
- Potencia generada  

En cada ciclo:
1. Genera valores aleatorios mediante `generate_random_values()`.  
2. Escribe esos valores en los registros de retención del servidor.  
3. Solicita su lectura inmediatamente después.  
4. Muestra por consola los valores escritos y leídos.

📄 **Archivo:** [ModbusTCP_client.py](./ModbusTCP_client.py)


## ModbusTCP_Server_v2.py

Este script inicializa un **servidor Modbus TCP** en el host local (`192.168.0.82/24`), escuchando en el **puerto 1502**.  
Define la **memoria de aplicación** del dispositivo como cuatro bloques consecutivos de **9999 registros** cada uno, correspondientes a:

- Entradas discretas (*Discrete Inputs*)
- Bobinas (*Coils*)
- Registros de entrada (*Input Registers*)
- Registros de retención (*Holding Registers*)

Cada solicitud recibida desde un cliente activa una **operación local de lectura o escritura** en la memoria del servidor, generando la **respuesta Modbus o excepción** correspondiente según el tipo de mensaje.  

Además, el servidor implementa una clase personalizada (`CustomDataBlock`) que **detecta cambios en los registros de retención** e imprime por consola los nuevos valores cuando estos se modifican.

📄 **Archivo:** [ModbusTCP_server_v2.py](./ModbusTCP_server_v2.py)



