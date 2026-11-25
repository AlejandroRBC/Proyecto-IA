"""Pruebas de la captura en vivo sin red: flujos armados a mano y paquetes de scapy en memoria."""

import csv
import json
import math
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import pytest

from src.alertas.gestor_alertas import COLUMNAS_HISTORIAL, registrar_flujo_analizado
from src.app import datos_panel as dp
from src.captura.capturador import (
    ORIGEN_CAPTURA,
    construir_filtro,
    convertir_paquete,
    evaluar_flujos,
    registrar_evaluados,
)
from src.captura.flujos import ICMP, TCP, UDP, Paquete, TablaFlujos

PC2, PC1 = "192.168.1.10", "192.168.1.7"


def tcp(t, origen, destino, sport, dport, carga=0, syn=False, fin=False, rst=False):
    return Paquete(t, origen, destino, TCP, sport, dport, carga, syn=syn, fin=fin, rst=rst)


def conexion_completa(tabla, t0=100.0):
    """PC2:50000 -> PC1:8080: handshake, petición, respuesta y cierre con FIN de ambos lados."""
    paquetes = [
        tcp(t0 + 0.000, PC2, PC1, 50000, 8080, syn=True),
        tcp(t0 + 0.001, PC1, PC2, 8080, 50000, syn=True),          # SYN-ACK
        tcp(t0 + 0.002, PC2, PC1, 50000, 8080),                    # ACK
        tcp(t0 + 0.003, PC2, PC1, 50000, 8080, carga=100),         # petición
        tcp(t0 + 0.005, PC1, PC2, 8080, 50000, carga=1000),        # respuesta
        tcp(t0 + 0.006, PC2, PC1, 50000, 8080, fin=True),
        tcp(t0 + 0.007, PC1, PC2, 8080, 50000, fin=True),
    ]
    cerrados = []
    for p in paquetes:
        cerrados += tabla.agregar_paquete(p)
    return cerrados


# ---------- Flujos y características ----------

def prueba_conexion_tcp_se_cierra_con_fin_y_calcula_caracteristicas():
    tabla = TablaFlujos()
    cerrados = conexion_completa(tabla)
    assert len(cerrados) == 1 and not tabla.activos
    flujo = cerrados[0]
    assert flujo.motivo_cierre == "fin"
    c = flujo.caracteristicas()
    assert c["Flow Duration"] == pytest.approx(7000)            # 7 ms en microsegundos
    assert c["Total Fwd Packets"] == 4 and c["Total Backward Packets"] == 3
    assert c["Total Length of Fwd Packets"] == 100 and c["Total Length of Bwd Packets"] == 1000
    assert c["Flow Bytes/s"] == pytest.approx(1100 / 0.007)
    assert c["Flow Packets/s"] == pytest.approx(7 / 0.007)
    assert c["Flow IAT Mean"] == pytest.approx(7000 / 6)
    assert c["SYN Flag Count"] == 2
    assert c["Destination Port"] == 8080                         # el puerto del que recibe la conexión


def prueba_ack_final_no_crea_flujo_fantasma():
    tabla = TablaFlujos()
    conexion_completa(tabla)
    assert tabla.agregar_paquete(tcp(100.008, PC2, PC1, 50000, 8080)) == []
    assert not tabla.activos


def prueba_rst_cierra_el_flujo_de_inmediato():
    """Así se ve un puerto cerrado en el escaneo: SYN y RST."""
    tabla = TablaFlujos()
    assert tabla.agregar_paquete(tcp(1.0, PC2, PC1, 40000, 22, syn=True)) == []
    cerrados = tabla.agregar_paquete(tcp(1.001, PC1, PC2, 22, 40000, rst=True))
    assert [f.motivo_cierre for f in cerrados] == ["rst"]
    assert cerrados[0].caracteristicas()["Destination Port"] == 22


def prueba_flujo_inactivo_expira_y_ping_es_un_solo_flujo():
    tabla = TablaFlujos(timeout_inactividad=5)
    for i in range(3):
        tabla.agregar_paquete(Paquete(10.0 + i, PC2, PC1, ICMP, carga_util=32))
        tabla.agregar_paquete(Paquete(10.0 + i + 0.001, PC1, PC2, ICMP, carga_util=32))
    assert tabla.expirar(14.0) == []                              # todavía dentro del tiempo
    cerrados = tabla.expirar(20.0)
    assert len(cerrados) == 1 and cerrados[0].motivo_cierre == "inactividad"
    c = cerrados[0].caracteristicas()
    assert (c["Total Fwd Packets"], c["Total Backward Packets"], c["Destination Port"]) == (3, 3, 0)


def prueba_paquete_tras_inactividad_abre_un_flujo_nuevo():
    tabla = TablaFlujos(timeout_inactividad=5)
    tabla.agregar_paquete(Paquete(0.0, PC2, PC1, UDP, 5000, 53, 40))
    cerrados = tabla.agregar_paquete(Paquete(10.0, PC2, PC1, UDP, 5000, 53, 40))
    assert len(cerrados) == 1 and len(tabla.activos) == 1


def prueba_flujo_de_un_paquete_tiene_tasas_infinitas_como_en_el_dataset():
    tabla = TablaFlujos()
    tabla.agregar_paquete(Paquete(0.0, PC2, PC1, UDP, 5000, 53, 40))
    c = tabla.vaciar()[0].caracteristicas()
    assert c["Flow Duration"] == 0 and math.isinf(c["Flow Bytes/s"]) and math.isinf(c["Flow Packets/s"])


def prueba_tiempos_invalidos():
    with pytest.raises(ValueError):
        TablaFlujos(timeout_inactividad=0)


# ---------- Conversión de paquetes de scapy (en memoria, sin red) ----------

def prueba_convertir_paquete_tcp_udp_icmp():
    from scapy.all import ICMP as SICMP, IP, TCP as STCP, UDP as SUDP, Ether, Raw

    syn = Ether() / IP(src=PC2, dst=PC1) / STCP(sport=50000, dport=8080, flags="S")
    datos = Ether() / IP(src=PC2, dst=PC1) / STCP(sport=50000, dport=8080, flags="PA") / Raw(b"x" * 10)
    udp = Ether() / IP(src=PC2, dst=PC1) / SUDP(sport=5000, dport=53) / Raw(b"y" * 7)
    ping = Ether() / IP(src=PC2, dst=PC1) / SICMP() / Raw(b"z" * 32)

    p = convertir_paquete(Ether(bytes(syn)))
    assert (p.protocolo, p.puerto_destino, p.syn, p.fin, p.carga_util) == (TCP, 8080, True, False, 0)
    assert convertir_paquete(Ether(bytes(datos))).carga_util == 10
    assert convertir_paquete(Ether(bytes(udp))).carga_util == 7
    p = convertir_paquete(Ether(bytes(ping)))
    assert (p.protocolo, p.puerto_origen, p.carga_util) == (ICMP, 0, 32)


def prueba_convertir_ignora_padding_ethernet():
    """Un SYN mide menos de 60 bytes: Ethernet lo rellena y ese relleno no es carga útil."""
    from scapy.all import IP, TCP as STCP, Ether

    trama = bytes(Ether() / IP(src=PC2, dst=PC1) / STCP(flags="S")) + b"\x00" * 6
    assert convertir_paquete(Ether(trama)).carga_util == 0


def prueba_convertir_ignora_lo_que_no_es_ipv4():
    from scapy.all import ARP, Ether

    assert convertir_paquete(Ether() / ARP()) is None


# ---------- Filtro ----------

def prueba_filtro_solo_pc2_y_todo_el_trafico():
    assert construir_filtro(PC2, True) == f"host {PC2} and ip and (tcp or udp or icmp)"
    assert construir_filtro(None, False) == "ip and (tcp or udp or icmp)"
    with pytest.raises(ValueError):
        construir_filtro("", True)


# ---------- Evaluación y registro (con un modelo falso) ----------

class ModeloFalso:
    """Devuelve -1 (anómalo) para el puerto 22 y +1 (normal) para el resto."""

    def decision_function(self, X):
        return np.where(X[:, -1] == 22, -1.0, 1.0)


def detector_falso():
    return {"modelo": ModeloFalso(), "umbral": -0.157, "orden_columnas": [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "SYN Flag Count", "Destination Port"]}


def prueba_evaluar_y_registrar_flujos_capturados(tmp_path):
    tabla = TablaFlujos()
    flujos = conexion_completa(tabla)                                         # NORMAL
    tabla.agregar_paquete(tcp(1.0, PC2, PC1, 40000, 22, syn=True))
    flujos += tabla.agregar_paquete(tcp(1.001, PC1, PC2, 22, 40000, rst=True))  # ANOMALO
    tabla.agregar_paquete(Paquete(5.0, PC2, PC1, UDP, 5000, 53, 40))
    flujos += tabla.vaciar()                                                  # NO_EVALUABLE (1 paquete)

    evaluados = evaluar_flujos(detector_falso(), flujos)
    assert [e["resultado"] for e in evaluados] == ["NORMAL", "ANOMALO", "NO_EVALUABLE"]
    assert all(e["archivo_origen"] == ORIGEN_CAPTURA and e["ip_origen"] == PC2 for e in evaluados)

    rutas = {"alertas": tmp_path / "alertas.csv", "flujos_analizados": tmp_path / "historial.csv",
             "flujos_capturados": tmp_path / "capturados.csv"}
    registrar_evaluados(evaluados, rutas)
    historial = pd.read_csv(rutas["flujos_analizados"])
    assert list(historial.columns) == COLUMNAS_HISTORIAL
    assert historial["ip_destino"].tolist() == [PC1] * 3
    assert len(pd.read_csv(rutas["alertas"])) == 1
    capturados = pd.read_csv(rutas["flujos_capturados"])  # "Infinity" se lee como inf
    assert math.isinf(capturados.loc[2, "Flow Bytes/s"])


# ---------- Historial: cambio de formato ----------

def prueba_historial_con_encabezado_viejo_se_respalda(tmp_path):
    ruta = tmp_path / "flujos_analizados.csv"
    ruta.write_text("fecha_hora,id_flujo,archivo_origen,puerto_destino,score,umbral,resultado\n"
                    "2026-01-01,f0,demo.csv,80,0.1,-0.15,NORMAL\n", encoding="utf-8")
    registrar_flujo_analizado(ruta, {"id_flujo": "f1", "ip_origen": PC2, "resultado": "NORMAL"})
    with open(ruta, newline="", encoding="utf-8") as f:
        filas = list(csv.reader(f))
    assert filas[0] == COLUMNAS_HISTORIAL and len(filas) == 2
    respaldos = list(tmp_path.glob("flujos_analizados.anterior-*.csv"))
    assert len(respaldos) == 1 and "f0" in respaldos[0].read_text(encoding="utf-8")


# ---------- Panel en vivo ----------

def prueba_captura_activa_segun_estado(tmp_path):
    ahora = datetime(2026, 11, 25, 15, 0, 0)
    reciente = {"activo": True, "actualizado": (ahora - timedelta(seconds=2)).isoformat()}
    viejo = {"activo": True, "actualizado": (ahora - timedelta(seconds=60)).isoformat()}
    assert dp.captura_activa(reciente, ahora)
    assert not dp.captura_activa(viejo, ahora)                    # proceso cerrado de golpe
    assert not dp.captura_activa({**reciente, "activo": False}, ahora)
    assert not dp.captura_activa(None, ahora)

    ruta = tmp_path / "estado.json"
    assert dp.leer_estado_captura(ruta) is None
    ruta.write_text(json.dumps(reciente), encoding="utf-8")
    assert dp.leer_estado_captura(ruta) == reciente
    ruta.write_text("{a medias", encoding="utf-8")
    assert dp.leer_estado_captura(ruta) is None


def prueba_flujos_en_vivo_y_resumen_por_ip():
    historial = pd.DataFrame({
        "archivo_origen": ["Monday.csv", ORIGEN_CAPTURA, ORIGEN_CAPTURA, ORIGEN_CAPTURA],
        "ip_origen": [None, PC2, PC2, "192.168.1.1"],
        "resultado": ["ANOMALO", "ANOMALO", "NORMAL", "NORMAL"],
        "score": [-0.3, -0.2, 0.1, 0.2],
    })
    vivo = dp.flujos_en_vivo(historial)
    assert len(vivo) == 3 and set(dp.COLUMNAS_VIVO) <= set(vivo.columns)
    resumen = dp.resumen_por_ip_origen(vivo)
    fila = resumen[resumen["IP origen"] == PC2].iloc[0]
    assert (fila["Flujos"], fila["Anómalos"], fila["Proporción anómala"]) == (2, 1, 0.5)
    assert dp.flujos_en_vivo(None).empty
    assert dp.flujos_en_vivo(historial.drop(columns="archivo_origen")).empty
