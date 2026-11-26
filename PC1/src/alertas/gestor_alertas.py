"""Gestor de alertas: guarda en un CSV solo los flujos marcados como ANOMALO.

El tráfico normal no se escribe en las alertas. El historial completo de flujos
es un archivo aparte y explícito (``registrar_flujo_analizado``).
"""

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

COLUMNAS_ALERTA = [
    "fecha_hora",
    "id_flujo",
    "ip_origen",
    "ip_destino",
    "puerto_origen",
    "puerto_destino",
    "score",
    "umbral",
    "resultado",
    "tipo_ataque",
]

# Historial completo (todos los flujos evaluados, no solo las alertas).
# ip_origen, ip_destino y puerto_origen se llenan con la captura en vivo
# (en la demo con CSV quedan vacías porque el dataset no trae IPs).
COLUMNAS_HISTORIAL = [
    "fecha_hora",
    "id_flujo",
    "archivo_origen",
    "ip_origen",
    "ip_destino",
    "puerto_origen",
    "puerto_destino",
    "score",
    "umbral",
    "resultado",
    "tipo_ataque",
    "id_incidente",
]


def registrar_alerta(ruta_csv: str | Path, info: dict) -> None:
    """Agrega una fila al CSV de alertas.

    Crea la carpeta y el encabezado si no existen. Si ``info`` no trae
    ``fecha_hora``, usa la hora actual. Los campos ausentes o ``None`` quedan
    vacíos y las claves extra se ignoran.
    """
    _agregar_fila(ruta_csv, COLUMNAS_ALERTA, info)


def registrar_flujo_analizado(ruta_csv: str | Path, info: dict) -> None:
    """Agrega una fila al historial completo, sin importar el resultado.

    A diferencia de ``registrar_alerta``/``procesar_resultado``, aquí se
    escribe todo flujo evaluado (NORMAL, ANOMALO o NO_EVALUABLE). Lo usa el
    panel para mostrar conteos y la gráfica de puntajes.
    """
    _agregar_fila(ruta_csv, COLUMNAS_HISTORIAL, info)


def registrar_incidente(ruta_csv: str | Path, info: dict) -> None:
    """Agrega una actualización de un incidente (una fila por actualización, con ``id_incidente``).

    El panel muestra la última fila de cada ``id_incidente``.
    """
    from src.clasificacion.reglas import COLUMNAS_INCIDENTE

    _agregar_fila(ruta_csv, COLUMNAS_INCIDENTE, info)


def _agregar_fila(ruta_csv: str | Path, columnas: list[str], info: dict) -> None:
    """Escribe ``info`` como una fila nueva y crea la carpeta y el encabezado si faltan.

    Si ``info`` no trae ``fecha_hora``, usa la hora actual. Los campos ausentes
    o ``None`` quedan vacíos y las claves extra se ignoran.
    """
    ruta = Path(ruta_csv)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    _respaldar_si_cambio_encabezado(ruta, columnas)
    escribir_encabezado = not ruta.exists() or ruta.stat().st_size == 0

    fila = {c: info.get(c) for c in columnas}
    if not fila["fecha_hora"]:
        fila["fecha_hora"] = datetime.now().isoformat(timespec="seconds")
    fila = {k: ("" if v is None else v) for k, v in fila.items()}

    with open(ruta, "a", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=columnas)
        if escribir_encabezado:
            escritor.writeheader()
        escritor.writerow(fila)


def _respaldar_si_cambio_encabezado(ruta: Path, columnas: list[str]) -> Path | None:
    """Si el CSV existe con otras columnas (versión anterior), lo renombra a un respaldo.

    Así nunca se mezclan filas con formatos distintos en el mismo archivo.
    Devuelve la ruta del respaldo o ``None`` si no hizo falta.
    """
    if not ruta.exists() or ruta.stat().st_size == 0:
        return None
    with open(ruta, newline="", encoding="utf-8") as f:
        encabezado = next(csv.reader(f), [])
    if encabezado == columnas:
        return None
    marca = datetime.now().strftime("%Y%m%d-%H%M%S")
    respaldo = ruta.with_name(f"{ruta.stem}.anterior-{marca}{ruta.suffix}")
    ruta.rename(respaldo)
    return respaldo


def procesar_resultado(ruta_csv: str | Path, fila_evaluada: dict) -> bool:
    """Registra la alerta solo si ``resultado == "ANOMALO"``. Devuelve si se registró."""
    if fila_evaluada.get("resultado") != "ANOMALO":
        return False
    registrar_alerta(ruta_csv, fila_evaluada)
    return True
