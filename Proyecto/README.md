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


## GUI_v16.py

Este script inicializa la **Interfaz Gráfica de Usuario (GUI)** de la herramienta de monitoreo Modbus TCP.  
La interfaz está estructurada en pestañas que permiten al usuario **capturar y analizar paquetes**, **realizar descubrimiento de red**, **visualizar métricas en tiempo real**, **registrar datos históricos** y **gestionar alarmas**.


### Estructura y funcionamiento

El código define la estructura de una **Unidad de Datos de Aplicación (ADU)** Modbus, que incluye:
- La **cabecera MBAP** (Modbus Application Protocol Header)  
- La **Unidad de Datos de Protocolo (PDU)** para solicitudes y respuestas  

Esta estructura se utiliza para **interpretar las tramas capturadas**, extrayendo y decodificando los campos relevantes del protocolo.

Además, se implementa un **mapeo de códigos de función y códigos de excepción**, lo que permite mostrar mensajes descriptivos y acciones correspondientes a cada operación Modbus detectada.


### Pestañas de la interfaz

La interfaz está organizada en cinco pestañas principales, cada una asociada a una funcionalidad específica:


#### 1. Captura Modbus TCP

Permite capturar paquetes de red en tiempo real utilizando la función `sniff()` de la librería Scapy.

**Elementos de la pestaña:**
- **Panel superior:** muestra la lista de paquetes capturados.  
- **Panel inferior izquierdo:** vista detallada del paquete seleccionado.  
- **Panel inferior derecho:** vista en formato hexadecimal.  
- **Controles:** botones *Iniciar captura*, *Detener captura* y un campo para establecer el número máximo de paquetes.

**Funcionamiento:**
- Cada paquete interceptado se agrega a la tabla principal.  
- Al seleccionar uno, se muestra la decodificación detallada por capas (L2, L3, L4 y aplicación).  
- Se identifican solicitudes y respuestas, mostrando:
  - ID de transacción  
  - Código de función y descripción  
  - Dirección inicial  
  - Número de bobinas/registros  
  - Valores leídos/escritos  
  - Códigos y descripciones de excepciones, si las hay  


#### 2. Descubrimiento de red

Permite realizar un **escaneo de red** escribiendo el rango de direcciones (por ejemplo, `192.168.0.0/24`).  
Al presionar el botón *Descubrimiento de red*, se ejecuta un análisis con **Nmap**, y los resultados se muestran en una tabla con:

- Dirección IP  
- Nombre de host  
- Estado del host  
- Dirección MAC  

Además, en el panel derecho se visualiza la **topología de red** en forma gráfica.


#### 3. Métricas de red

Muestra en tiempo real las métricas de desempeño de la red:

- **RTT (Round Trip Time)**  
- **Jitter**  
- **Throughput**

**Distribución visual:**
- **Panel izquierdo:** gráficos de evolución temporal.  
- **Panel derecho:** valores instantáneos actualizados y contadores de:
  - Paquetes totales  
  - Tramas correctas  
  - Tramas erróneas  


#### 4. Registro de métricas

Presenta un **historial temporal** de las métricas capturadas, organizado en una tabla donde cada fila representa una instantánea con:
- Estampa de tiempo  
- Valores de RTT, jitter y throughput  
- Contadores acumulativos  

Esto permite analizar la evolución del desempeño a lo largo del tiempo.


#### 5. Alarmas

Supervisa en tiempo real la **cantidad de tramas erróneas capturadas**.  
Cuando el número de errores supera el umbral de **30 paquetes**, el sistema:

- Genera una **alerta visual** mediante una ventana emergente  
- Registra el evento en la tabla de alarmas con:
  - Estampa de tiempo  
  - Tipo de alarma  
  - Comentario descriptivo  


### Funciones adicionales

La herramienta permite **exportar los datos** capturados en distintos formatos:

- `.pcap` → para análisis con herramientas externas (como Wireshark)  
- `.csv` → para tratamiento estadístico o visualización posterior  

Estas exportaciones pueden realizarse tanto para los **paquetes capturados** como para las **métricas registradas**.


📄 **Archivo:** [GUI_v16.py](./GUI_v16.py)





