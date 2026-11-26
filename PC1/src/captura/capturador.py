"""Captura en vivo con scapy (requiere Npcap en Windows) y evaluación de cada flujo.

Ciclo:  paquete (hilo de scapy) → cola → TablaFlujos → flujo cerrado →
        detector (por lotes) → clasificador de ataques (reglas por ventana + Random Forest) →
        alertas.csv / flujos_analizados.csv / flujos_capturados.csv / incidentes.csv

El hilo de scapy solo convierte y encola paquetes. Todo lo demás corre en el
hilo principal, una vez por segundo, así la tabla de flujos no necesita candados.
"""

from __future__ import annotations

import csv
import json
import math
import time
from collections import Counter, deque
from datetime import datetime
from pathlib import Path

import pandas as pd

from src.alertas.gestor_alertas import (
    _respaldar_si_cambio_encabezado,
    procesar_resultado,
    registrar_flujo_analizado,
    registrar_incidente,
)
from src.captura.flujos import ICMP, TCP, UDP, Flujo, Paquete, TablaFlujos
from src.clasificacion.reglas import describir_incidente
from src.modelo.detector import ANOMALO, NO_EVALUABLE, evaluar_lote

ORIGEN_CAPTURA = "captura_en_vivo"

# Columnas del CSV con las características crudas de cada flujo capturado
# (sirve para revisar los valores y, más adelante, entrenar un modelo del laboratorio).
COLUMNAS_FLUJOS_CAPTURADOS = [
    "fecha_hora", "inicio_flujo", "fin_flujo", "id_flujo", "protocolo",
    "ip_origen", "ip_destino", "puerto_origen", "puerto_destino", "motivo_cierre",
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "SYN Flag Count", "Destination Port",
    "score", "umbral", "resultado", "tipo_ataque", "id_incidente", "familia_rf", "prob_rf",
]


def construir_filtro(ip_pc2: str | None, solo_trafico_pc2: bool) -> str:
    """Filtro BPF: solo TCP/UDP/ICMP sobre IPv4 y, opcionalmente, solo el tráfico de PC2."""
    base = "ip and (tcp or udp or icmp)"
    if solo_trafico_pc2:
        if not ip_pc2:
            raise ValueError("Falta captura.ip_pc2 (o --ip-pc2) para filtrar solo el tráfico de PC2.")
        return f"host {ip_pc2} and {base}"
    return base


def convertir_paquete(pkt) -> Paquete | None:
    """Paquete de scapy → ``Paquete``. Devuelve ``None`` si no es IPv4 TCP/UDP/ICMP."""
    from scapy.layers.inet import ICMP as CapaICMP
    from scapy.layers.inet import IP
    from scapy.layers.inet import TCP as CapaTCP
    from scapy.layers.inet import UDP as CapaUDP

    if IP not in pkt:
        return None
    ip = pkt[IP]
    if ip.frag or ip.flags.MF:  # fragmentos: se ignoran (no aparecen en la demo)
        return None
    # La carga útil se calcula con las longitudes de las cabeceras para no
    # contar el relleno (padding) de Ethernet.
    cuerpo = int(ip.len) - int(ip.ihl) * 4
    tiempo = float(pkt.time)
    if CapaTCP in pkt:
        tcp = pkt[CapaTCP]
        banderas = int(tcp.flags)
        return Paquete(tiempo, ip.src, ip.dst, TCP, int(tcp.sport), int(tcp.dport),
                       max(cuerpo - int(tcp.dataofs) * 4, 0),
                       syn=bool(banderas & 0x02), fin=bool(banderas & 0x01), rst=bool(banderas & 0x04))
    if CapaUDP in pkt:
        udp = pkt[CapaUDP]
        return Paquete(tiempo, ip.src, ip.dst, UDP, int(udp.sport), int(udp.dport), max(cuerpo - 8, 0))
    if CapaICMP in pkt:
        return Paquete(tiempo, ip.src, ip.dst, ICMP, 0, 0, max(cuerpo - 8, 0))
    return None


def _iso(segundos: float) -> str:
    return datetime.fromtimestamp(segundos).isoformat(timespec="milliseconds")


def _texto(valor):
    """Infinitos/NaN como texto legible en el CSV de características."""
    if isinstance(valor, float) and (math.isinf(valor) or math.isnan(valor)):
        return "Infinity" if math.isinf(valor) else ""
    return valor


def evaluar_flujos(detector: dict, flujos: list[Flujo]) -> list[dict]:
    """Evalúa varios flujos con una sola llamada al modelo y devuelve filas listas para los CSV."""
    if not flujos:
        return []
    filas = [f.como_fila() for f in flujos]
    evaluados = evaluar_lote(detector, pd.DataFrame(filas))
    ahora = datetime.now().isoformat(timespec="milliseconds")
    salida = []
    for flujo, fila, (_, ev) in zip(flujos, filas, evaluados.iterrows()):
        score = None if pd.isna(ev["score"]) else float(ev["score"])
        salida.append({
            **fila,
            "fecha_hora": ahora,
            "inicio_flujo": _iso(flujo.inicio),
            "fin_flujo": _iso(flujo.ultimo),
            "archivo_origen": ORIGEN_CAPTURA,
            "score": score,
            "umbral": detector["umbral"],
            "resultado": ev["resultado"],
        })
    return salida


def registrar_evaluados(evaluados: list[dict], rutas: dict) -> None:
    """Escribe alertas, historial y características crudas."""
    if not evaluados:
        return
    for fila in evaluados:
        procesar_resultado(rutas["alertas"], fila)
        registrar_flujo_analizado(rutas["flujos_analizados"], fila)
    ruta = Path(rutas["flujos_capturados"])
    ruta.parent.mkdir(parents=True, exist_ok=True)
    _respaldar_si_cambio_encabezado(ruta, COLUMNAS_FLUJOS_CAPTURADOS)
    nuevo = not ruta.exists() or ruta.stat().st_size == 0
    with open(ruta, "a", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=COLUMNAS_FLUJOS_CAPTURADOS, extrasaction="ignore")
        if nuevo:
            escritor.writeheader()
        for fila in evaluados:
            escritor.writerow({k: _texto("" if fila.get(k) is None else fila.get(k))
                               for k in COLUMNAS_FLUJOS_CAPTURADOS})


def escribir_estado(ruta: Path, estado: dict) -> bool:
    """Escribe el JSON de estado que lee el panel. Nunca lanza: devuelve si pudo escribir.

    En Windows no se puede renombrar un archivo mientras otro proceso (el panel, cada
    2 s) lo tiene abierto, y ese fallo no debe detener la captura. Se reintenta el
    renombrado y, si sigue fallando, se escribe directamente sobre el archivo final.
    """
    ruta = Path(ruta)
    texto = json.dumps(estado, ensure_ascii=False, indent=2)
    try:
        ruta.parent.mkdir(parents=True, exist_ok=True)
        temporal = ruta.with_suffix(".tmp")
        temporal.write_text(texto, encoding="utf-8")
        for intento in range(5):
            try:
                temporal.replace(ruta)
                return True
            except PermissionError:
                time.sleep(0.05 * (intento + 1))
        ruta.write_text(texto, encoding="utf-8")   # plan B: sobrescribir en el sitio
        temporal.unlink(missing_ok=True)
        return True
    except OSError:
        return False  # el estado es solo informativo; se reintenta en el siguiente ciclo


def describir(fila: dict) -> str:
    marca = {"ANOMALO": "[ANOMALO]", "NORMAL": "[NORMAL] ", NO_EVALUABLE: "[NO_EVAL]"}[fila["resultado"]]
    score = "   --   " if fila["score"] is None else f"{fila['score']:+.4f}"
    tipo = f"  <{fila['tipo_ataque']}>" if fila.get("tipo_ataque") else ""
    return (f"{marca} score={score}  {fila['protocolo']:<4} {fila['ip_origen']}:{fila['puerto_origen']}"
            f" -> {fila['ip_destino']}:{fila['puerto_destino']}  paquetes="
            f"{fila['Total Fwd Packets']}/{fila['Total Backward Packets']}  ({fila['motivo_cierre']}){tipo}")


def capturar(
    detector: dict,
    rutas: dict,
    interfaz: str | None,
    filtro: str,
    timeout_inactividad: float,
    timeout_activo: float,
    duracion: float | None = None,
    mostrar_normales: bool = True,
    clasificador=None,
) -> Counter:
    """Captura hasta Ctrl+C (o hasta ``duracion`` segundos). Devuelve el conteo de resultados."""
    # scapy.all registra todas las capas (Ethernet, IP...); sin eso no decodifica los paquetes.
    from scapy.all import AsyncSniffer

    cola: deque[Paquete] = deque()

    def al_recibir(pkt) -> None:
        paquete = convertir_paquete(pkt)
        if paquete is not None:
            cola.append(paquete)

    tabla = TablaFlujos(timeout_inactividad, timeout_activo)
    conteo: Counter = Counter()
    inicio = time.time()
    estado = {
        "activo": True, "inicio": _iso(inicio), "interfaz": interfaz or "(predeterminada)",
        "filtro": filtro, "modelo": detector.get("nombre", "base"), "umbral": detector["umbral"],
        "paquetes": 0, "flujos_activos": 0, "flujos_evaluados": 0,
        "anomalos": 0, "no_evaluables": 0,
        "clasificacion": clasificador is not None,
        "random_forest": bool(clasificador is not None and clasificador.rf is not None),
        "incidentes": 0, "incidentes_por_tipo": {},
    }

    def procesar(cerrados: list[Flujo]) -> None:
        evaluados = evaluar_flujos(detector, cerrados)
        nuevos: list[dict] = []
        if clasificador is not None and evaluados:
            tocados, nuevos = clasificador.procesar(evaluados)
            if "incidentes" in rutas:
                for incidente in tocados:
                    registrar_incidente(rutas["incidentes"], incidente)
        registrar_evaluados(evaluados, rutas)
        for fila in evaluados:
            conteo[fila["resultado"]] += 1
            if mostrar_normales or fila["resultado"] != "NORMAL":
                print(describir(fila))
        for incidente in nuevos:
            print(describir_incidente(incidente))

    def actualizar_estado(activo: bool = True) -> None:
        estado.update(
            activo=activo, actualizado=_iso(time.time()), paquetes=tabla.paquetes_procesados,
            flujos_activos=len(tabla.activos), flujos_evaluados=sum(conteo.values()),
            anomalos=conteo[ANOMALO], no_evaluables=conteo[NO_EVALUABLE],
        )
        if clasificador is not None:
            estado.update(incidentes=clasificador.total_incidentes,
                          incidentes_por_tipo=clasificador.conteo_por_tipo())
        escribir_estado(rutas["estado_captura"], estado)

    sniffer = AsyncSniffer(iface=interfaz, filter=filtro, prn=al_recibir, store=False)
    sniffer.start()
    time.sleep(0.5)
    if not sniffer.running:
        raise RuntimeError("No se pudo iniciar la captura (¿Npcap instalado? ¿interfaz correcta?).")
    actualizar_estado()
    try:
        while duracion is None or time.time() - inicio < duracion:
            time.sleep(1)
            cerrados = []
            while cola:
                cerrados += tabla.agregar_paquete(cola.popleft())
            cerrados += tabla.expirar(time.time())
            procesar(cerrados)
            actualizar_estado()
    except KeyboardInterrupt:
        print("\nDeteniendo la captura...")
    finally:
        try:
            sniffer.stop()
        except Exception:  # noqa: BLE001 — si ya se detuvo, no importa
            pass
        cerrados = []
        while cola:
            cerrados += tabla.agregar_paquete(cola.popleft())
        procesar(cerrados + tabla.vaciar())
        actualizar_estado(activo=False)
    return conteo
