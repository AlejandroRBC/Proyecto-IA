"""Carga de configuración y de los CSV de CICIDS2017.

Este módulo solo lee datos y limpia nombres de columna. La limpieza de valores
(infinitos, nulos, duplicados) vive en ``caracteristicas.py``.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import yaml

# Carpeta raíz de PC1 (este archivo está en PC1/src/procesamiento/).
RAIZ_PC1 = Path(__file__).resolve().parents[2]
RUTA_CONFIG_POR_DEFECTO = RAIZ_PC1 / "configuracion.yaml"


class ErrorColumnas(ValueError):
    """Se lanza cuando faltan columnas requeridas en un DataFrame o CSV."""


def cargar_configuracion(ruta: str | Path | None = None) -> dict:
    """Lee el YAML de configuración y resuelve las rutas relativas.

    Las rutas de la sección ``rutas`` se resuelven respecto a la carpeta del
    archivo YAML, así los scripts funcionan sin depender del directorio actual.
    """
    ruta = Path(ruta) if ruta else RUTA_CONFIG_POR_DEFECTO
    with open(ruta, encoding="utf-8") as f:
        config = yaml.safe_load(f)
    base = ruta.resolve().parent
    config["rutas"] = {k: (base / v).resolve() for k, v in config["rutas"].items()}
    return config


def limpiar_nombres_columnas(df: pd.DataFrame) -> pd.DataFrame:
    """Quita espacios al inicio y final de los nombres de columna."""
    df = df.copy()
    df.columns = df.columns.str.strip()
    return df


def columnas_requeridas(config: dict) -> list[str]:
    """Las 10 características más la columna de etiqueta."""
    return list(config["caracteristicas"]) + [config["datos"]["columna_etiqueta"]]


def verificar_columnas(config: dict, archivo: str | None = None) -> list[str]:
    """Fase 1: lee una fila del CSV y confirma que existan las columnas requeridas.

    Devuelve la lista de columnas encontradas (ya limpias). Lanza ``ErrorColumnas``
    si falta alguna.
    """
    archivo = archivo or config["datos"]["archivo_entrenamiento"]
    ruta = config["rutas"]["datos_crudos"] / archivo
    df = pd.read_csv(ruta, nrows=1, encoding=config["datos"]["codificacion"])
    df = limpiar_nombres_columnas(df)
    faltantes = [c for c in columnas_requeridas(config) if c not in df.columns]
    if faltantes:
        raise ErrorColumnas(f"En '{archivo}' faltan las columnas: {faltantes}")
    print(f"[verificación] '{archivo}': {len(df.columns)} columnas; "
          f"las {len(config['caracteristicas'])} características y "
          f"'{config['datos']['columna_etiqueta']}' existen.")
    return list(df.columns)


def cargar_csv(config: dict, archivo: str) -> pd.DataFrame:
    """Carga un CSV leyendo solo las columnas requeridas (ahorra memoria).

    Los nombres se comparan tras ``.strip()`` porque los CSV originales traen
    espacios al inicio de casi todas las columnas.
    """
    ruta = config["rutas"]["datos_crudos"] / archivo
    requeridas = set(columnas_requeridas(config))
    df = pd.read_csv(
        ruta,
        usecols=lambda c: c.strip() in requeridas,
        encoding=config["datos"]["codificacion"],
        low_memory=False,
    )
    df = limpiar_nombres_columnas(df)
    faltantes = requeridas - set(df.columns)
    if faltantes:
        raise ErrorColumnas(f"En '{archivo}' faltan las columnas: {sorted(faltantes)}")
    etiqueta = config["datos"]["columna_etiqueta"]
    df[etiqueta] = df[etiqueta].astype(str).str.strip()
    print(f"[carga] {archivo}: {len(df):,} filas")
    return df


def cargar_entrenamiento(config: dict) -> pd.DataFrame:
    """Carga el CSV de entrenamiento (lunes)."""
    return cargar_csv(config, config["datos"]["archivo_entrenamiento"])


def cargar_evaluacion(config: dict) -> pd.DataFrame:
    """Carga y concatena todos los CSV de evaluación (martes a viernes)."""
    partes = [cargar_csv(config, a) for a in config["datos"]["archivos_evaluacion"]]
    df = pd.concat(partes, ignore_index=True)
    print(f"[carga] evaluación concatenada: {len(df):,} filas")
    return df
