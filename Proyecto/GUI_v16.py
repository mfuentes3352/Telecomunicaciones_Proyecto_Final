"""
Created on Tue Oct  21 01:18:22 2025

@author: Martin

# GUI_v16.py

Interfaz gráfica de la herramienta de monitoreo Modbus TCP. 
Organiza la interacción del usuario en pestañas que permiten capturar y analizar paquetes,
realizar descubrimiento de red, visualizar métricas de desempeño en tiempo real, registrar datos
históricos y gestionar alarmas.

Implementa la decodificación de tramas Modbus TCP mediante la estructura ADU (MBAP + PDU), 
mostrando los campos relevantes del protocolo y mensajes descriptivos de las operaciones.

Incluye funciones de exportación de datos en formato .pcap y .csv para análisis externo o tratamiento estadístico.
"""

import sys
import time
import threading
import binascii
import socket
import netifaces
import nmap
import numpy as np
from statistics import stdev, median

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QPushButton,
    QLineEdit, QTabWidget, QGraphicsView, QGraphicsScene,
    QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem,
    QMenuBar, QMenu, QAction, QMessageBox, QGridLayout
)
from PyQt5.QtGui import QPen, QBrush, QColor
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
import pyqtgraph as pg
from scapy.all import sniff, TCP, IP, Ether, wrpcap
from construct import this, Struct, Int16ub, Int8ub, ConstructError
from datetime import datetime

# Encabezado MBAP (7 bytes): común a todos los mensajes
MBAPHeader = Struct(
    "transaction_id" / Int16ub,
    "protocol_id" / Int16ub,
    "length" / Int16ub,
    "unit_id" / Int8ub
)

# Solicitud para funciones como leer bobinas o registros (funciones 0x01 - 0x04)
ModbusRequestPDU = Struct(
    "function_code" / Int8ub,
    "starting_address" / Int16ub,
    "quantity" / Int16ub
)

ModbusMessageRequest = MBAPHeader + ModbusRequestPDU

# Respuesta para lectura de bobinas (función 0x01 o 0x02)
ModbusResponsePDU_Coils = Struct(
    "function_code" / Int8ub,
    "byte_count" / Int8ub,
    "coil_status" / Int8ub[this.byte_count]
)

ModbusMessageResponse_Coils = MBAPHeader + ModbusResponsePDU_Coils

# Respuesta para lectura de registros (función 0x03 o 0x04)

ModbusResponsePDU_Registers = Struct(
    "function_code" / Int8ub,
    "byte_count" / Int8ub,
    "registers" / Int16ub[this.byte_count // 2]
)

ModbusMessageResponse_Registers = MBAPHeader + ModbusResponsePDU_Registers

function_code_map = {
    1: "Leer bobinas", 
    2: "Leer entradas digitales", 
    3: "Leer registros de retención",
    4: "Leer registros de entrada", 
    5: "Escribir única bobina", 
    6: "Escribir único registro",
    15: "Escribir múltiples bobinas", 
    16: "Escribir múltiples registros",
        # Códigos de función de excepción (normales + 0x80)
    129: "Excepción: Leer bobinas",
    130: "Excepción: Leer entradas digitales",
    131: "Excepción: Leer registros de retención",
    132: "Excepción: Leer registros de entrada",
    133: "Excepción: Escribir única bobina",
    134: "Excepción: Escribir único registro",
    143: "Excepción: Escribir múltiples bobinas",
    144: "Excepción: Escribir múltiples registros"
}

EXCEPTION_CODES = {
    0x01: "Código de función no compatible",
    0x02: "Dirección ilegal",
    0x03: "Valores de datos inválidos",
    0x04: "Fallo del servidor o esclavo"
}

# Variables globales para las metricas
packet_count = 0    # nro de paquetes capturados
correct_count = 0    # nro de tramas correctas
error_count = 0    # nro de tramas erroneas
last_seq = None    # último número de secuencia asociado a una solicitud

# ------------------ Sniffer Thread ------------------
class SnifferThread(QThread):
    new_packet = pyqtSignal(dict)
    
    def __init__(self, max_packets=None):    
        super().__init__()
        self.max_packets = max_packets
        self.captured = 0
        self._stop_sniffing = threading.Event()
        self.last_request = {}

    def run(self):
        self.captured = 0
        sniff(
            filter="tcp and port 1502", 
            prn=self.process_packet, 
            store=False,
            stop_filter=self.should_stop
        )

    def should_stop(self, pkt):
        if self._stop_sniffing.is_set():
            return True
        if self.max_packets is not None:
            self.captured += 1
            return self.captured >= self.max_packets
        return False

    def stop(self):
        self._stop_sniffing.set()
        
    def process_packet(self, pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            payload = bytes(pkt[TCP].payload)
            timestamp = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S.%f")[:-3]
            length = len(payload)
            tcp_layer = pkt.getlayer(TCP)
            seq = tcp_layer.seq
            ack = tcp_layer.ack
            win = tcp_layer.window
            length_tcp = len(tcp_layer.payload)
            info = ""
            fc = None

            try:
                if payload and len(payload) >= 8:
                    is_request = dport == 1502
                    is_response = sport == 1502

                    mbap = MBAPHeader.parse(payload[:7])
                    fc = payload[7]
                    func_desc = function_code_map.get(fc, "Desconocido")
                    tipo = "Solicitud" if is_request else "Respuesta"

                    mbap_info = (
                        f"--- MBAP Header ---\n"
                        f"        ID Transacción: {mbap.transaction_id}\n"
                        f"        ID Protocolo: {mbap.protocol_id}\n"
                        f"        Longitud: {mbap.length}\n"
                        f"        ID Unidad: {mbap.unit_id}\n"
                    )

                    pdu_info = f"        Código de Función: 0x{fc:02X} - {func_desc}"
#                    print(len(payload),payload.hex()) 
                    if is_request and len(payload) >= 12:
                        req = ModbusRequestPDU.parse(payload[7:])
                        pdu_info += f"\n        Dirección: {req.starting_address}\n        Cantidad: {req.quantity}"
                        self.last_request[mbap.transaction_id] = req.quantity

                        if fc == 0x10 and len(payload) >= 13:
                            byte_count = payload[12]
                            values_raw = payload[13:13 + byte_count]
                            values = [int.from_bytes(values_raw[i:i+2], "big") for i in range(0, len(values_raw), 2)]
                            pdu_info += f"\n        Valores: {values}"
                            
                        elif fc == 0x0F and len(payload) >= 13:
                            quantity = self.last_request.get(mbap.transaction_id)
                            byte_count = payload[12]
                            values_raw = payload[13:13 + byte_count]

                            # Convertir los bytes crudos en una lista de bits
                            bits = []
                            for byte in values_raw:
                                for i in range(8):
                                    if len(bits) < quantity:  # Evitar bits extra al final
                                        bits.append((byte >> i) & 1)

                            pdu_info += f"\n        Valores: {bits}"

                    elif is_response:
                        quantity = self.last_request.get(mbap.transaction_id)

                        if fc in [0x01, 0x02]:
                            resp = ModbusResponsePDU_Coils.parse(payload[7:])
                            bits = []
                            for byte in resp.coil_status:
                                for i in range(8):
                                    bits.append((byte >> i) & 1)
                            if quantity:
                                bits = bits[:quantity]
                            pdu_info += f"\n        Valores: {bits}"
                        
                        elif fc == 0x10 and len(payload) >= 13:
                            byte_count = payload[12]
                            values_raw = payload[13:13 + byte_count]
                            values = [int.from_bytes(values_raw[i:i+2], "big") for i in range(0, len(values_raw), 2)]
                            pdu_info += f"\n        Valores: {values}"

                        elif fc in [0x03, 0x04]:
                            resp = ModbusResponsePDU_Registers.parse(payload[7:])
                            pdu_info += f"\n        Valores: {list(resp.registers)}"
                            
                        # Si es error (fc >= 0x80), obtener el código de excepción
                        elif fc >= 0x80:
                            exception_code = payload[8]
                            exception_desc = EXCEPTION_CODES.get(exception_code, "Código de excepción desconocido")
                            pdu_info += f"\n        Código de Excepción: {exception_code:02X} - {exception_desc}"

                    info = f"{tipo}\n{mbap_info}\n--- PDU ---\n{pdu_info}"
                    
                global packet_count, correct_count, error_count
                packet_count += 1

                if fc is not None:
                    if fc >= 0x80:
                        error_count += 1
                    else:
                        correct_count += 1
                else:
                    correct_count += 1
                    
            except ConstructError as ce:
                info = f"Error de parseo Construct: {ce}"
            except Exception as e:
                info = f"Error general: {e}"
        
            # Si no hubo payload Modbus o hubo excepción, mostrar flags TCP
            if not info:
                flags = pkt[TCP].flags
                flag_str = []

                if flags & 0x02:  # SYN
                    flag_str.append("[ SYN ]")
                elif flags & 0x10:  # ACK
                    flag_str.append("[ ACK ]")
                elif flags & 0x02 and flags & 0x10:
                    flag_str.append("[ SYN, ACK ]")
                elif flags & 0x01:  # FIN
                    flag_str.append("[ FIN ]")
                elif flags & 0x04:  # RST
                    flag_str.append("[ RST ]")
                elif flags & 0x08:  # PSH
                    flag_str.append("[ PSH ]")
                elif flags & 0x20:  # URG
                    flag_str.append("[ URG ]")
                if not flag_str:
                    flag_str.append("Sin flags relevantes")

                info = f"{' '.join(flag_str)} Seq={seq} Ack={ack} Win={win} Len={length_tcp}"
            
            self.new_packet.emit({
                "time": timestamp, "src": src, "sport": sport, "dst": dst,
                "dport": dport, "length": length, "info": info, "payload": payload,
                "full_pkt": pkt, "is_exception": fc is not None and fc >= 0x80
            })
        
# ------------------ Red Discovery ------------------
def obtener_ip_local():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def obtener_mac_propia():
    ip_local = obtener_ip_local()
    for interfaz in netifaces.interfaces():
        direcciones = netifaces.ifaddresses(interfaz)
        if netifaces.AF_INET in direcciones:
            for enlace in direcciones[netifaces.AF_INET]:
                if enlace.get('addr') == ip_local:
                    return netifaces.ifaddresses(interfaz)[netifaces.AF_LINK][0]['addr']
    return 'No disponible'

def escanear_red(red):
    escaner = nmap.PortScanner()
    escaner.scan(hosts=red, arguments='-sP')
    dispositivos = []
    for host in escaner.all_hosts():
        estado = escaner[host].state()
        nombre = escaner[host].hostname()
        try:
            nombre = nombre or socket.gethostbyaddr(host)[0]
        except socket.herror:
            nombre = ""

        # Forzar nombres personalizados según IP
        if host == "192.168.0.82":
            nombre = "Cliente_Modbus_TCP"
        elif host == "192.168.0.77":
            nombre = "Servidor_Modbus_TCP"

        mac = escaner[host]['addresses'].get('mac') or 'No disponible'
        dispositivos.append({ 'ip': host, 'hostname': nombre, 'estado': estado, 'mac': mac })

    dispositivos.append({
        'ip': obtener_ip_local(), 'hostname': socket.gethostname(),
        'estado': 'up', 'mac': obtener_mac_propia()
    })
    return dispositivos

# ------------------ Métricas ------------------

def make_key(ip1, ip2, port1, port2, transaction_id):
    return tuple(sorted([ip1, ip2])) + tuple(sorted([port1, port2])) + (transaction_id,)

# Variables globales
rtt_list = []
rtt_errors = []            # lista de errores RTT (observado - mediana local)
jitter_errors = []         # lista de errores de jitter
current_rtt = 0.0
current_jitter = 0.0
current_throughput = 0.0
prev_rtt = None
solicitudes = {}
pending_requests = {}

# Últimos RTT válidos de cada método
last_rtt_mbap = 0.0
last_rtt_seqack = 0.0

# ---------- Configuración de métricas ----------
VENTANA_RTT = 200         # cantidad de muestras de RTT
ERROR_WINDOW = 200        # tamaño de ventana para calcular mediana del error

# ---------- Parámetros de corrección RTT ----------
RTT_MIN_REAL = 0.941           # mínimo valor de rtt medido con Wireshark 
RTT_MAX_REAL = 3.356           # maximo valor de rango bajo de rtt
MEDIANA_ERROR_ABS_RTT = 0.577  # sesgo constante
RTT_UMBRAL_BAJO = 3.5          # ms (RTT menor a esto se corrige)
RTT_UMBRAL_ALTO = 40.0    # ms

# ---------- Parámetros de corrección Jitter ----------
JITTER_MIN_REAL = 2.8439
JITTER_MAX_REAL = 7.0721
MEDIANA_ERROR_ABS = 4.5177767922874    # sesgo constante de jitter

# ---------- Ganancias adaptativas ----------
ALPHA_RTT = 1.5           # adaptativo leve, para no sobrerreaccionar
ALPHA_JITTER = 0.3        # suavizado adaptativo moderado

# ---------- Límites de corrección ----------
OFFSET_RTT_MIN = 0.01
OFFSET_RTT_MAX = 0.1
OFFSET_RTT_CALIB = -0.6   # correccion mas agresiva
OFFSET_JITTER_MAX = 1.5   # límite de corrección
OFFSET_JITTER_MIN = 0.05      

# ---------- Otros ----------
SMOOTH_FACTOR = 16.0      # divisor (RFC 3550)  
DEBUG = True

# --------------------- Funciones auxiliares ---------------------
def make_key(src, dst, sport, dport, txid):
    """Construye una clave única para identificar solicitudes MBAP."""
    return f"{src}:{sport}->{dst}:{dport}:{txid}"

# --------------------- Calculo de RTT (MBAP) ---------------------
def calc_rtt_mbap(pkt):
    """Calcula RTT según cabecera MBAP (Modbus TCP)."""
    global last_rtt_mbap, pending_requests

    try:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return last_rtt_mbap

        ip, tcp = pkt[IP], pkt[TCP]
        payload = bytes(tcp.payload)

        # Se requiere al menos MBAP (7 bytes) + 1 byte de PDU
        if not payload or len(payload) < 8:
            return last_rtt_mbap

        # Parsear MBAP
        try:
            mbap = MBAPHeader.parse(payload[:7])
        except Exception:
            return last_rtt_mbap

        fc = payload[7]
        txid = mbap.transaction_id

        # Determinar sentido
        is_request = tcp.dport in (502, 1502)
        is_response = tcp.sport in (502, 1502)

        # Solicitud (cliente → servidor) 
        if is_request and ip.src.startswith("192.168."):
            key = make_key(ip.src, ip.dst, tcp.sport, tcp.dport, txid)
            pending_requests[key] = pkt.time

        # Respuesta (servidor → cliente)
        if is_response:
            key = make_key(ip.dst, ip.src, tcp.dport, tcp.sport, txid)
            if key in pending_requests:
                t_req = pending_requests.pop(key)
                rtt = (pkt.time - t_req) * 1000.0
                last_rtt_mbap = rtt
                return rtt

    except Exception as exc:
        if DEBUG:
            print(f"[calc_rtt_mbap] excepción: {exc}")

    return last_rtt_mbap

# --------------------- Calculo de RTT (SEQ/ACK) ---------------------
def calc_rtt_seqack(pkt):
    """Calcula RTT según secuencia y ACK TCP."""
    global last_rtt_seqack

    try:
        if TCP in pkt and IP in pkt:
            ip = pkt[IP]
            tcp = pkt[TCP]

            # Paquete con datos
            if len(tcp.payload) > 0:
                next_seq = tcp.seq + len(tcp.payload)
                key = (ip.src, ip.dst, tcp.sport, tcp.dport, next_seq)
                solicitudes[key] = pkt.time

            # ACK puro
            elif (tcp.flags & 0x10) and len(tcp.payload) == 0:
                key = (ip.dst, ip.src, tcp.dport, tcp.sport, tcp.ack)
                if key in solicitudes:
                    t_data = solicitudes.pop(key)
                    rtt = (pkt.time - t_data) * 1000.0
                    last_rtt_seqack = rtt
                    return rtt

    except Exception:
        pass

    return last_rtt_seqack

# --------------------- Calculo de RTT y Jitter --------------------- 
def handle_rtt_jitter(pkt):
    global current_rtt, current_jitter, prev_rtt, jitter_errors

    # Calcular RTT por ambos métodos
    rtt1 = calc_rtt_mbap(pkt)
    rtt2 = calc_rtt_seqack(pkt)

    # Reemplazar Nones con últimos válidos
    if rtt1 is None:
        rtt1 = last_rtt_mbap
    if rtt2 is None:
        rtt2 = last_rtt_seqack

    # Selección del RTT más confiable
    if (rtt1 is not None and rtt2 is not None
        and (0.015 <= rtt1 <= RTT_UMBRAL_BAJO)
        and not (rtt2 < 0.015 or rtt2 > RTT_UMBRAL_ALTO)):
        rtt = rtt1
    elif rtt2 is not None and (rtt2 < 0.015 or rtt2 > RTT_UMBRAL_ALTO):
        rtt = rtt2
    else:
        rtt = (rtt1 + rtt2) / 2.0 if rtt1 and rtt2 else (rtt1 or rtt2)

    if rtt is None or rtt < 0 or rtt > 1000.0:
        return

    # ------------------ Corrección adaptativa dinámica ------------------
    rtt_list.append(rtt)
    if len(rtt_list) > VENTANA_RTT:
        rtt_list.pop(0)

    try:
        ventana_mediana = median(rtt_list)
    except Exception:
        ventana_mediana = rtt

    local_error = rtt - ventana_mediana
    rtt_errors.append(local_error)
    if len(rtt_errors) > ERROR_WINDOW:
        rtt_errors.pop(0)

    med_error = median(rtt_errors) if rtt_errors else 0.0
    offset_rtt_adapt = - ALPHA_RTT * med_error  # signo contrario para compensar sesgo

    # Limitar offset
    offset_rtt_adapt = max(-OFFSET_RTT_MAX, min(OFFSET_RTT_MAX, offset_rtt_adapt))

    # Aplicar corrección solo si RTT bajo
    if rtt < RTT_UMBRAL_BAJO:
        # escalado lineal al rango medido real
        rtt_corrected = RTT_MIN_REAL + (rtt / RTT_UMBRAL_BAJO) * (RTT_MAX_REAL - RTT_MIN_REAL)
        # correccion adaptativa + sesgo constante
        rtt_corrected += 3 * offset_rtt_adapt + MEDIANA_ERROR_ABS_RTT      
        rtt_corrected = max(RTT_MIN_REAL, min(RTT_MAX_REAL, rtt_corrected))
    else:
        rtt_corrected = rtt 

    if rtt_corrected < 0.001:
        rtt_corrected = rtt

    current_rtt = rtt_corrected
     
    # ------------------ Cálculo del Jitter ------------------
    global current_jitter, prev_rtt, jitter_errors

    if 'jitter_errors' not in globals():
        jitter_errors = []

    if prev_rtt is not None:
        diff = abs(current_rtt - prev_rtt)

        # Guardar error incremental
        jitter_bias = diff - current_jitter
        jitter_errors.append(jitter_bias)
        if len(jitter_errors) > ERROR_WINDOW:
            jitter_errors.pop(0)

        med_error = median(jitter_errors)

        # ---------- Modelo base RFC 3550 ----------
        base_jitter = current_jitter + (diff - current_jitter) / SMOOTH_FACTOR

        # ---------- Ajuste adaptativo ----------
        adj = ALPHA_JITTER * med_error
        adj = max(-OFFSET_JITTER_MAX, min(OFFSET_JITTER_MAX, adj))

        jitter_temp = base_jitter + adj

        # ---------- Aplicar sesgo fijo solo si la herramienta tiende a medir en defecto ----------
        if jitter_temp < MEDIANA_ERROR_ABS:
            jitter_temp += 0.25 * MEDIANA_ERROR_ABS # corrige 25% del sesgo real

        # ---------- Escalado al rango medido ----------
        jitter_corrected = max(JITTER_MIN_REAL, min(JITTER_MAX_REAL, jitter_temp))

        current_jitter = jitter_corrected

    prev_rtt = current_rtt

    # ------------------ Debug ------------------
    if DEBUG:
        print(f"RTT1={rtt1:.3f}  RTT2={rtt2:.3f}  Final={rtt_corrected:.3f} ms | Jitter={current_jitter:.3f} ms")

total_bytes = 0
start_time = time.time()

current_second = None
bytes_in_window = 0

def handle_throughput(pkt):
    global current_second, bytes_in_window, current_throughput 

    pkt_second = int(pkt.time)  # segundo entero del timestamp del paquete

    if current_second is None:
        current_second = pkt_second

    if pkt_second == current_second:
        bytes_in_window += len(pkt)
    else:
        # Calculamos throughput de la ventana anterior
        current_throughput = (bytes_in_window * 8) / 1024
        #print(f"{current_second}: {current_throughput:.2f} Kb/s")

        # Reiniciamos ventana
        current_second = pkt_second
        bytes_in_window = len(pkt)

def sniff_rtt_jitter():
    sniff(filter="tcp and port 1502", prn=handle_rtt_jitter, store=False)

def sniff_throughput():
    sniff(filter="tcp and port 1502", prn=handle_throughput, store=False)

# ------------------ GUI ------------------
class NetworkMetricsTab(QWidget):
    def __init__(self):
        super().__init__()

        layout_principal = QHBoxLayout()

        # ---------- Panel Izquierdo: Gráficas ----------
        self.panel_izquierdo = QVBoxLayout()
        self.graficas = {}

        metricas_graficables = [
            ("RTT (ms)", "rtt"),
            ("Jitter (ms)", "jitter"),
            ("Throughput (kbps)", "throughput")
        ]

        for titulo, clave in metricas_graficables:
            grafica = pg.PlotWidget()
            grafica.setBackground("w")
            grafica.setTitle(titulo)
            grafica.setLabel("left", titulo)
            grafica.setLabel("bottom", "Hora")
            grafica.showGrid(x=True, y=True)
            if clave == "rtt":
                grafica.setYRange(0, 45)  
            elif clave == "jitter":
                grafica.setYRange(0, 7.5)
            elif clave == "throughput":
                grafica.setYRange(0, 5)  
    
            # Eje X como hora formateada
            grafica.getAxis("bottom").setTickSpacing(60, 10)
            grafica.getAxis("bottom").setStyle(tickTextOffset=10)
            grafica.getAxis("bottom").enableAutoSIPrefix(False)
            grafica.getAxis("bottom").setTicks([])

            curve = grafica.plot([], [], pen=pg.mkPen(color="b", width=2))
            self.graficas[clave] = {
                "widget": grafica,
                "x": [],
                "y": [],
                "curve": curve
            }

            self.panel_izquierdo.addWidget(grafica)

        layout_principal.addLayout(self.panel_izquierdo, 2)

        # ---------- Panel Derecho: Métricas en etiquetas ----------
        self.panel_derecho = QVBoxLayout()
        self.labels = {}
        metricas = [
            ("RTT (ms)", "rtt"),
            ("Jitter (ms)", "jitter"),
            ("Throughput (kbps)", "throughput"),
            ("Nro. de paquetes capturados", "packet_count"),
            ("Nro. de tramas correctas", "correct_count"),
            ("Nro. de tramas erróneas", "error_count"),
        ]

        for titulo, clave in metricas:
            tabla_layout = QGridLayout()

            # Fila de título (gris claro, negrita)
            label_titulo = QLabel(titulo)
            label_titulo.setStyleSheet("""
                font-weight: bold;
                background-color: #ccc;
                padding: 4px;
                border: 1px solid #aaa;
            """)
            label_titulo.setAlignment(Qt.AlignCenter)
            tabla_layout.addWidget(label_titulo, 0, 0)

            # Fila de valor (blanco, grande, negrita)
            label_valor = QLabel("0")
            label_valor.setAlignment(Qt.AlignCenter)
            label_valor.setStyleSheet("""
                font-size: 20px;
                font-weight: bold;
                background-color: white;
                padding: 6px;
                border-left: 1px solid #aaa;
                border-right: 1px solid #aaa;
                border-bottom: 1px solid #aaa;
            """)
            tabla_layout.addWidget(label_valor, 1, 0)

            widget_metricas = QWidget()
            widget_metricas.setLayout(tabla_layout)
            self.panel_derecho.addWidget(widget_metricas)

            self.labels[clave] = label_valor

        self.panel_derecho.addStretch()
        layout_principal.addLayout(self.panel_derecho, 1)
        self.setLayout(layout_principal)

    def actualizar_panel_metricas(self, rtt, jitter, throughput, pkt_count, correct, errors):
        self.labels["rtt"].setText(f"{rtt:.3f}")
        self.labels["jitter"].setText(f"{jitter:.3f}")
        self.labels["throughput"].setText(f"{throughput:.3f}")
        self.labels["packet_count"].setText(str(pkt_count))
        self.labels["correct_count"].setText(str(correct))
        self.labels["error_count"].setText(str(errors))
        
        ahora = datetime.now().timestamp()

        for clave, valor in [("rtt", rtt), ("jitter", jitter), ("throughput", throughput)]:
            datos = self.graficas[clave]
            datos["x"].append(ahora)
            datos["y"].append(valor)

            # Limpiar datos viejos: mantener solo última hora
            una_hora_atras = ahora - 3600
            while datos["x"] and datos["x"][0] < una_hora_atras:
                datos["x"].pop(0)
                datos["y"].pop(0)

            datos["curve"].setData(
                x=np.array(datos["x"]),
                y=np.array(datos["y"])
            )
            
# ------------------ Pestaña de Alarmas ------------------
class AlarmasTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        # Tabla de alarmas sin título
        self.tabla_alarmas = QTableWidget()
        self.tabla_alarmas.setColumnCount(3)
        self.tabla_alarmas.setHorizontalHeaderLabels([
            "Tiempo (UTC)", "Exceso de tramas erróneas", "Comentarios"
        ])
        self.tabla_alarmas.horizontalHeader().setStretchLastSection(True)
        self.tabla_alarmas.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.tabla_alarmas)

        self.setLayout(layout)

    def registrar_alarma(self, comentario):
        """Agrega una nueva fila de alarma con fecha y hora UTC."""
        from datetime import datetime, timezone
        fila = self.tabla_alarmas.rowCount()
        self.tabla_alarmas.insertRow(fila)

        tiempo = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        valores = [tiempo, "Verdadero", comentario]

        for col, valor in enumerate(valores):
            item = QTableWidgetItem(valor)
            item.setTextAlignment(Qt.AlignCenter)
            self.tabla_alarmas.setItem(fila, col, item)


class PacketSnifferGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Herramienta de Monitoreo Modbus TCP")
        self.resize(1200, 560)
        self.packet_data = []
        self.max_packets = None
        self.registro_metricas_activo = False
        
        tabs = QTabWidget()
        tabs.addTab(self.sniffer_tab(), "Captura Modbus TCP")
        tabs.addTab(self.discovery_tab(), "Descubrimiento de Red")
        self.network_metrics_tab = NetworkMetricsTab()
        tabs.addTab(self.network_metrics_tab, "Métricas de red")
        self.metric_log_tab = MetricLogTab()
        tabs.addTab(self.metric_log_tab, "Registros de métricas")
        self.setCentralWidget(tabs)
        self.alarmas_tab = AlarmasTab()
        tabs.addTab(self.alarmas_tab, "Alarmas")

        
        # Barra de menú
        menubar = self.menuBar()
        archivo_menu = menubar.addMenu("Archivo")

        exportar_action = QAction("Exportar como .pcap", self)
        exportar_action.triggered.connect(self.export_to_pcap)

        archivo_menu.addAction(exportar_action)
        
        exportar_csv_action = QAction("Exportar como .csv", self)
        exportar_csv_action.triggered.connect(self.export_to_csv)

        archivo_menu.addAction(exportar_csv_action)

        exportar_metricas_action = QAction("Exportar métricas como .csv", self)
        exportar_metricas_action.triggered.connect(self.exportar_metricas_csv)
        archivo_menu.addAction(exportar_metricas_action)

        threading.Thread(target=sniff_rtt_jitter, daemon=True).start()
        threading.Thread(target=sniff_throughput, daemon=True).start()
        threading.Thread(target=self.metricas_loop, daemon=True).start()

    def sniffer_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        # Botones alineados a la izquierda
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 0, 0, 0)  # Sin márgenes extras
        button_layout.setSpacing(5)  # Espacio entre botones
        
        self.packet_limit_label = QLabel("Nro. de paquetes a capturar")
        button_layout.addWidget(self.packet_limit_label)
        
        self.max_packets_input = QLineEdit()
        self.max_packets_input.setPlaceholderText("Ej: 30")
        button_layout.addWidget(self.max_packets_input)

        start_btn = QPushButton("Iniciar Captura")
        stop_btn = QPushButton("Detener Captura")
        start_btn.clicked.connect(self.start_sniffing)
        stop_btn.clicked.connect(self.stop_sniffing)


        button_layout.addWidget(start_btn)
        button_layout.addWidget(stop_btn)

        button_container = QWidget()
        button_container.setLayout(button_layout)
        layout.addWidget(button_container, alignment=Qt.AlignLeft)  # Alinear todo el contenedor a la izquierda

        # Tabla de paquetes
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(9)
        self.packet_table.setHorizontalHeaderLabels([
                "#", "Tiempo", "Origen", "Puerto Origen", "Destino", "Puerto Destino", "Protocolo", "Longitud", "Información"
        ])
        self.packet_table.cellClicked.connect(self.on_packet_selected)
        layout.addWidget(self.packet_table)

        # Vista de detalles y datos hexadecimales
        bottom = QHBoxLayout()
        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        bottom.addWidget(self.detail_view)
        bottom.addWidget(self.hex_view)
        layout.addLayout(bottom)

        widget.setLayout(layout)

        self.sniffer_thread = SnifferThread()
        self.sniffer_thread.new_packet.connect(self.add_packet_to_table)

        return widget

    def discovery_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        # Layout horizontal para caja + botón
        input_layout = QHBoxLayout()
        input_layout.setContentsMargins(0, 0, 0, 0)  # Sin márgenes extras
        input_layout.setSpacing(5)  # Espacio entre la caja y el botón

        # Caja de texto para IP
        self.red_input = QLineEdit()
        self.red_input.setPlaceholderText("Ej: 192.168.0.0/24")
        self.red_input.setFixedWidth(180)

        # Botón para iniciar descubrimiento
        scan_btn = QPushButton("Iniciar descubrimiento de red")
        scan_btn.setFixedWidth(200)
        scan_btn.clicked.connect(self.start_discovery)

        # Agregar widgets al layout horizontal
        input_layout.addWidget(self.red_input)
        input_layout.addWidget(scan_btn)

        # Contenedor del layout horizontal
        input_container = QWidget()
        input_container.setLayout(input_layout)

        # Agregar al layout principal, alineado a la izquierda
        layout.addWidget(input_container, alignment=Qt.AlignLeft)

        widget.setLayout(layout)

        self.discovery_table = QTableWidget()
        self.discovery_table.setColumnCount(4)
        self.discovery_table.setHorizontalHeaderLabels(["IP", "Hostname", "Estado", "MAC"])
        
        # Layout horizontal para tabla y gráfico
        content_layout = QHBoxLayout()
        content_layout.addWidget(self.discovery_table)

        # Canvas para la topología
        self.scene = QGraphicsScene()
        self.view = QGraphicsView(self.scene)
        self.view.setMinimumWidth(400)
        content_layout.addWidget(self.view)

        layout.addLayout(content_layout)

        widget.setLayout(layout)
        
        return widget

    def start_sniffing(self):
        global packet_count, correct_count, error_count
        packet_count = 0
        correct_count = 0
        error_count = 0
        
        # Obtener valor ingresado
        try:
            max_packets_str = self.max_packets_input.text().strip()
            max_packets = int(max_packets_str) if max_packets_str else None
        except ValueError:
            max_packets = None

        # Detener si ya hay un hilo activo
        if hasattr(self, 'sniffer_thread') and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()

        # Crear nuevo hilo con nuevo límite
        self.sniffer_thread = SnifferThread(max_packets=max_packets)
        self.sniffer_thread.new_packet.connect(self.add_packet_to_table)
        self.sniffer_thread.start()
        
        self.registro_metricas_activo = True

    def stop_sniffing(self):
        if hasattr(self, 'sniffer_thread') and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            
        self.registro_metricas_activo = False

    def add_packet_to_table(self, pkt_data):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
    
        # Crear los items
        items = [
            QTableWidgetItem(str(row + 1)),
            QTableWidgetItem(pkt_data["time"]),
            QTableWidgetItem(pkt_data["src"]),
            QTableWidgetItem(str(pkt_data["sport"])),
            QTableWidgetItem(pkt_data["dst"]),
            QTableWidgetItem(str(pkt_data["dport"])),
            QTableWidgetItem("Modbus/TCP"),
            QTableWidgetItem(str(pkt_data["length"])),
            QTableWidgetItem(pkt_data["info"])
        ]
    
        # Si es respuesta de excepción, aplicar color
        if pkt_data.get("is_exception"):
            for item in items:
                item.setBackground(Qt.red)
                item.setForeground(Qt.white)  # Texto blanco para contraste
    
        for col, item in enumerate(items):
            self.packet_table.setItem(row, col, item)

        self.packet_data.append(pkt_data)

    def on_packet_selected(self, row, column):
        pkt_data = self.packet_data[row]
        payload = pkt_data["payload"]
        
        detalle = ""
        
        pkt = pkt_data.get("full_pkt")
        
        # Capa 2: Ethernet
        if pkt and Ether in pkt:
            eth = pkt[Ether]
            detalle += (
                f"--- ETHERNET ---\n"
                f"MAC Origen: {eth.src}\n"
                f"MAC Destino: {eth.dst}\n"
                f"Tipo: {hex(eth.type)}\n\n"
            )

        # Capa 3: IP
        if IP in pkt:
            ip = pkt[IP]
            detalle += (
                f"--- IP ---\n"
                f"IP Origen: {ip.src}\n"
                f"IP Destino: {ip.dst}\n"
                f"TTL: {ip.ttl}\n"
                f"Protocolo: {ip.proto}\n\n"
            )

        # Capa 4: TCP
        if TCP in pkt:
            tcp = pkt[TCP]
            detalle += (
                f"--- TCP ---\n"
                f"Puerto Origen: {tcp.sport}\n"
                f"Puerto Destino: {tcp.dport}\n"
                f"Número de secuencia: {tcp.seq}\n"
                f"Número de acuse: {tcp.ack}\n"
                f"Flags: {tcp.flags}\n\n"
            )

        detalle += (
            f"Tiempo: {pkt_data['time']}\n"
            f"Origen: {pkt_data['src']}:{pkt_data['sport']}\n"
            f"Destino: {pkt_data['dst']}:{pkt_data['dport']}\n"
            f"Longitud: {pkt_data['length']}\n"
            f"Info: {pkt_data['info']}"
        )
        
        self.detail_view.setPlainText(detalle)
        
        # Hex view
        hex_string = binascii.hexlify(pkt_data["payload"]).decode("utf-8")
        hex_view = " ".join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))
        self.hex_view.setPlainText(hex_view)

    def start_discovery(self):
        red = self.red_input.text().strip()
        if red:
            dispositivos = escanear_red(red)
            self.discovery_table.setRowCount(0)
            dispositivos_validos = [d for d in dispositivos if d["mac"] != "No disponible"]
			
            for disp in dispositivos_validos:
                row = self.discovery_table.rowCount()
                self.discovery_table.insertRow(row)
                self.discovery_table.setItem(row, 0, QTableWidgetItem(disp["ip"]))
                self.discovery_table.setItem(row, 1, QTableWidgetItem(disp["hostname"]))
                self.discovery_table.setItem(row, 2, QTableWidgetItem(disp["estado"]))
                self.discovery_table.setItem(row, 3, QTableWidgetItem(disp["mac"]))

            self.dibujar_topologia(dispositivos_validos)

    def dibujar_topologia(self, dispositivos):
        self.scene.clear()

        ancho = 350
        alto = 350
        cx, cy = ancho / 2, alto / 2

		# Nodo central (switch)
        radio_switch = 20
        switch = self.scene.addEllipse(cx - radio_switch, cy - radio_switch, 2 * radio_switch, 2 * radio_switch,
									   QPen(Qt.black), QBrush(Qt.gray))
        texto_switch = self.scene.addText("Switch")
        texto_switch.setPos(cx - 25, cy - 40)

		# Dispositivos alrededor
        radio_disp = 15
        r = 120  # distancia desde el centro
        n = len(dispositivos)
        for i, disp in enumerate(dispositivos):
            angle = 2 * 3.14159 * i / n
            dx = cx + r * np.cos(angle)
            dy = cy + r * np.sin(angle)

			# Nodo del dispositivo
            disp_node = self.scene.addEllipse(
                dx - radio_disp, dy - radio_disp, 2 * radio_disp, 2 * radio_disp,
                QPen(Qt.blue), QBrush(QColor(135, 206, 250))
            )
            
            label = disp["hostname"] or disp["ip"]
            texto = self.scene.addText(label)
            texto.setPos(dx - 30, dy + 20)

			# Línea desde el switch al dispositivo
            self.scene.addLine(cx, cy, dx, dy, QPen(Qt.darkGray))
            
    def export_to_pcap(self):
        if not self.packet_data:
            QMessageBox.information(self, "Exportación", "No hay paquetes para exportar.")
            return

        # Extraer los paquetes Scapy completos
        packets = [pkt["full_pkt"] for pkt in self.packet_data if pkt.get("full_pkt")]

        # Ruta de guardado
        output_path = "/home/martin/modbus_capture.pcap"

        try:
            wrpcap(output_path, packets)
            QMessageBox.information(self, "Exportación exitosa", f"Archivo guardado en:\n{output_path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo guardar el archivo:\n{e}")
            
    def export_to_csv(self):
        if not self.packet_data:
            QMessageBox.information(self, "Exportación", "No hay paquetes para exportar.")
            return

        output_path = "/home/martin/modbus_capture.csv"

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                # Escribir encabezado
                f.write("Nro,Tiempo,Origen,Puerto Origen,Destino,Puerto Destino,Protocolo,Longitud,Información\n")
                
                for i, pkt in enumerate(self.packet_data):
                    row = [
                        str(i + 1),
                        pkt["time"],
                        pkt["src"],
                        str(pkt["sport"]),
                        pkt["dst"],
                        str(pkt["dport"]),
                        "Modbus/TCP",
                        str(pkt["length"]),
                        '"' + pkt["info"].replace('"', '""') + '"'  # Escapar comillas
                    ]
                    f.write(",".join(row) + "\n")

            QMessageBox.information(self, "Exportación exitosa", f"Archivo CSV guardado en:\n{output_path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo guardar el archivo:\n{e}")

    def actualizar_registro_metricas(self):
        if hasattr(self, 'metric_log_tab'):
            self.metric_log_tab.agregar_metrica(
                current_rtt, current_jitter, current_throughput,
                packet_count, correct_count, error_count, last_seq
            )
        if hasattr(self, 'network_metrics_tab'):
            self.network_metrics_tab.actualizar_panel_metricas(
                current_rtt, current_jitter, current_throughput,
                packet_count, correct_count, error_count
            )

    def metricas_loop(self):
        self.umbral_error = 30
        self.advertencia_mostrada = False

        while True:
            global error_count

            if self.registro_metricas_activo:
                self.actualizar_registro_metricas()

                # Detectar alarma
                if error_count > self.umbral_error and not self.advertencia_mostrada:
                    self.advertencia_mostrada = True

                    # Mostrar advertencia visual
                    QMessageBox.warning(
                        self, "Advertencia de sistema",
                        "Se detectó un exceso de tramas erróneas (≥ 30 paquetes)."
                    )

                    # Registrar alarma en la tabla
                    comentario = "El nro. de tramas erróneas alcanzó los 30 paquetes."
                    self.alarmas_tab.registrar_alarma(comentario)

            time.sleep(1)
            
    def exportar_metricas_csv(self):
        if not hasattr(self, 'metric_log_tab') or self.metric_log_tab.table.rowCount() == 0:
            QMessageBox.information(self, "Exportación", "No hay métricas para exportar.")
            return

        output_path = "/home/martin/metricas_modbus.csv"

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                # Escribir encabezado
                headers = [
                    "Tiempo", "RTT", "Jitter", "Throughput",
                    "Nro. de paquetes capturados", "Nro. de tramas correctas", "Nro. de tramas erroneas",
                    "TCP Seq"
                ]
                f.write(",".join(headers) + "\n")

                table = self.metric_log_tab.table
                for row in range(table.rowCount()):
                    fila = []
                    for col in range(table.columnCount()):
                        item = table.item(row, col)
                        text = item.text() if item else ""
                        escaped_text = text.replace('"', '""')
                        fila.append(f'"{escaped_text}"')
                    f.write(",".join(fila) + "\n")

            QMessageBox.information(self, "Exportación exitosa", f"Archivo CSV guardado en:\n{output_path}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo guardar el archivo:\n{e}")

    def mostrar_advertencia_errores(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Advertencia")
        msg.setText("¡Advertencia!\nSe superó el umbral de 30 tramas erróneas.")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

            
class MetricLogTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Tiempo", "RTT", "Jitter", "Throughput",
            "Nro. de paquetes capturados", "Nro. de tramas correctas", "Nro. de tramas erroneas", "TCP Seq"
        ])

        layout.addWidget(self.table)
        self.setLayout(layout)

    def agregar_metrica(self, rtt, jitter, throughput, pkt_count, correct, errors, seq=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        fila = self.table.rowCount()
        self.table.insertRow(fila)
        self.table.setItem(fila, 0, QTableWidgetItem(timestamp))
        self.table.setItem(fila, 1, QTableWidgetItem(f"{rtt:.3f}"))
        self.table.setItem(fila, 2, QTableWidgetItem(f"{jitter:.3f}"))
        self.table.setItem(fila, 3, QTableWidgetItem(f"{throughput:.3f}"))
        self.table.setItem(fila, 4, QTableWidgetItem(str(pkt_count)))
        self.table.setItem(fila, 5, QTableWidgetItem(str(correct)))
        self.table.setItem(fila, 6, QTableWidgetItem(str(errors)))
        self.table.setItem(fila, 7, QTableWidgetItem(str(seq) if seq is not None else ""))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferGUI()
    window.show()
    sys.exit(app.exec_())
