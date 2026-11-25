"""Registro en CSV de los escenarios ejecutados, para correlacionar con PC1."""

import csv
import json
from datetime import datetime
from pathlib import Path

COLUMNAS = ["fecha_hora_inicio", "fecha_hora_fin", "tipo_escenario", "parametros", "ip_destino"]


def ahora() -> str:
    """Fecha y hora local con segundos, formato fácil de comparar con PC1."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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
    }
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
