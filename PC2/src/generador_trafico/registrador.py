"""Registro en CSV de los escenarios ejecutados, para correlacionar con PC1."""

import csv
import json
import socket
from datetime import datetime
from pathlib import Path

# ip_origen = IP de PC2 en ese momento. PC1 la usa para saber qué flujos capturados
# pertenecen a cada escenario (la IP de PC2 puede cambiar entre sesiones).
COLUMNAS = ["fecha_hora_inicio", "fecha_hora_fin", "tipo_escenario", "parametros", "ip_destino", "ip_origen"]


def ip_local_hacia(ip_destino: str) -> str:
    """IP de PC2 que el sistema usaría para llegar a ``ip_destino``.

    Un socket UDP con ``connect`` solo elige la ruta: no envía ningún paquete.
    Devuelve "" si no se puede determinar.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((ip_destino, 9))
            return s.getsockname()[0]
    except OSError:
        return ""


def _respaldar_si_cambio_encabezado(ruta: Path) -> None:
    """Si el CSV tiene el formato anterior, se renombra para no mezclar columnas."""
    if not ruta.exists() or ruta.stat().st_size == 0:
        return
    with open(ruta, newline="", encoding="utf-8") as archivo:
        encabezado = next(csv.reader(archivo), [])
    if encabezado != COLUMNAS:
        marca = datetime.now().strftime("%Y%m%d-%H%M%S")
        ruta.rename(ruta.with_name(f"{ruta.stem}.anterior-{marca}{ruta.suffix}"))


def ahora() -> str:
    """Fecha y hora local con milisegundos, para cruzarla con los flujos capturados en PC1."""
    return datetime.now().isoformat(sep=" ", timespec="milliseconds")


def registrar_escenario(ruta_csv, info: dict) -> None:
    """Agrega una fila al CSV; crea el archivo con encabezado si no existe."""
    ruta = Path(ruta_csv)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    parametros = info.get("parametros", "")
    if not isinstance(parametros, str):
        parametros = json.dumps(parametros, ensure_ascii=False)
    fila = {
        "fecha_hora_inicio": info.get("fecha_hora_inicio", ""),
        "fecha_hora_fin": info.get("fecha_hora_fin", ""),
        "tipo_escenario": info.get("tipo_escenario", ""),
        "parametros": parametros,
        "ip_destino": info.get("ip_destino", ""),
        "ip_origen": info.get("ip_origen", ""),
    }
    _respaldar_si_cambio_encabezado(ruta)
    nuevo = not ruta.exists() or ruta.stat().st_size == 0
    with open(ruta, "a", newline="", encoding="utf-8") as archivo:
        escritor = csv.DictWriter(archivo, fieldnames=COLUMNAS)
        if nuevo:
            escritor.writeheader()
        escritor.writerow(fila)


def leer_ultimos_escenarios(ruta_csv, cantidad: int = 10) -> list:
    """Devuelve las últimas `cantidad` filas del CSV (lista vacía si no existe)."""
    ruta = Path(ruta_csv)
    if not ruta.exists():
        return []
    with open(ruta, newline="", encoding="utf-8") as archivo:
        filas = list(csv.DictReader(archivo))
    return filas[-cantidad:]
