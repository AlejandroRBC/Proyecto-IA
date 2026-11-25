"""Detector: aplica el modelo entrenado y su umbral a flujos nuevos.

Se separan dos tipos de datos:
  * Características del modelo: las 10 columnas de ``metadatos["caracteristicas"]``.
    Son lo único que entra al modelo.
  * Datos de identificación (``id_flujo``, ``ip_origen``, ``ip_destino``,
    ``puerto_origen``, ``puerto_destino``): solo se usan para mostrar la alerta.
    Nunca entran al modelo y pueden venir vacíos.

A diferencia de ``caracteristicas.limpiar()``, pensada para lotes de
entrenamiento y evaluación, aquí no se eliminan duplicados ni se descartan filas
en silencio. Un flujo inválido se marca como ``NO_EVALUABLE``.

Este módulo no importa nada de ``entrenar.py`` ni de ``evaluar.py``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

import joblib
import numpy as np
import pandas as pd

from src.procesamiento.dataset import cargar_configuracion

NORMAL = "NORMAL"
ANOMALO = "ANOMALO"
NO_EVALUABLE = "NO_EVALUABLE"

CAMPOS_IDENTIFICACION = ["id_flujo", "ip_origen", "ip_destino", "puerto_origen", "puerto_destino"]


def cargar_detector(config: dict | None = None) -> dict:
    """Carga el modelo y sus metadatos una sola vez para reutilizarlos en cada predicción."""
    config = config or cargar_configuracion()
    dir_modelos = config["rutas"]["modelos"]
    modelo = joblib.load(dir_modelos / config["archivos_salida"]["modelo"])
    with open(dir_modelos / config["archivos_salida"]["metadatos"], encoding="utf-8") as f:
        metadatos = json.load(f)

    # orden_columnas se guarda como {nombre: posición}; se convierte a lista ordenada.
    orden = metadatos["orden_columnas"]
    orden_columnas = sorted(orden, key=orden.get) if isinstance(orden, dict) else list(orden)
    umbral = metadatos["umbral"]
    umbral = float(umbral["valor"] if isinstance(umbral, dict) else umbral)

    return {
        "modelo": modelo,
        "metadatos": metadatos,
        "orden_columnas": orden_columnas,
        "umbral": umbral,
    }


def _a_diccionario(datos) -> dict:
    """Convierte un dict, una Series o un DataFrame de una fila en dict con claves limpias."""
    if isinstance(datos, pd.DataFrame):
        if len(datos) != 1:
            raise ValueError(f"Se esperaba un solo flujo y llegaron {len(datos)} filas; usa evaluar_lote().")
        datos = datos.iloc[0]
    if isinstance(datos, pd.Series):
        datos = datos.to_dict()
    if not isinstance(datos, Mapping):
        raise TypeError(f"Tipo de flujo no soportado: {type(datos).__name__}")
    return {str(k).strip(): v for k, v in datos.items()}


def preparar_flujo_para_prediccion(datos, orden_columnas: list[str]) -> pd.DataFrame | None:
    """Deja un flujo listo para el modelo: DataFrame de una fila, numérico y en orden fijo.

    Devuelve ``None`` si falta alguna característica o si algún valor es NaN,
    infinito o no numérico. Quien llama decide qué hacer con ese flujo.
    No elimina duplicados.
    """
    flujo = _a_diccionario(datos)
    if any(c not in flujo for c in orden_columnas):
        return None

    fila = pd.DataFrame([[flujo[c] for c in orden_columnas]], columns=orden_columnas)
    fila = fila.apply(pd.to_numeric, errors="coerce").astype("float64")
    fila = fila.replace([np.inf, -np.inf], np.nan)
    if fila.isna().any(axis=None):
        return None
    return fila


def _clasificar(score: float, umbral: float) -> str:
    """Misma regla que en el entrenamiento: anómalo si decision_function < umbral."""
    return ANOMALO if score < umbral else NORMAL


def evaluar_flujo(detector: dict, datos) -> dict:
    """Evalúa un flujo y devuelve ``{"resultado", "score", "umbral"}``.

    ``datos`` puede venir preparado (salida de ``preparar_flujo_para_prediccion``)
    o crudo (dict/Series). Si no es evaluable, ``resultado`` es ``NO_EVALUABLE``
    y ``score`` es ``None``; no se lanza una excepción.
    """
    umbral = detector["umbral"]
    orden = detector["orden_columnas"]
    # Preparar un flujo ya preparado no hace daño: se revalida por si trae NaN o infinitos.
    preparado = None if datos is None else preparar_flujo_para_prediccion(datos, orden)

    if preparado is None:
        return {"resultado": NO_EVALUABLE, "score": None, "umbral": umbral}

    # El modelo se entrenó con arrays de numpy; se le pasa un array en el mismo orden.
    score = float(detector["modelo"].decision_function(preparado.to_numpy())[0])
    return {"resultado": _clasificar(score, umbral), "score": score, "umbral": umbral}


def evaluar_lote(detector: dict, df: pd.DataFrame) -> pd.DataFrame:
    """Evalúa cada fila de ``df`` y agrega las columnas ``resultado``, ``score`` y ``umbral``.

    Equivale a llamar a ``evaluar_flujo`` fila por fila, pero llama al modelo una
    sola vez para todas las filas válidas. Se conservan todas las columnas
    originales, incluidas las de identificación. Las filas inválidas quedan
    como ``NO_EVALUABLE``.
    """
    orden = detector["orden_columnas"]
    umbral = detector["umbral"]
    resultado = df.copy()
    resultado.columns = resultado.columns.astype(str).str.strip()

    faltantes = [c for c in orden if c not in resultado.columns]
    scores = pd.Series(np.nan, index=resultado.index, dtype="float64")
    if not faltantes:
        X = resultado[orden].apply(pd.to_numeric, errors="coerce").astype("float64")
        X = X.replace([np.inf, -np.inf], np.nan)
        validas = X.notna().all(axis=1)
        if validas.any():
            scores[validas] = detector["modelo"].decision_function(X[validas].to_numpy())

    resultado["score"] = scores
    resultado["resultado"] = [
        NO_EVALUABLE if pd.isna(s) else _clasificar(s, umbral) for s in scores
    ]
    resultado["umbral"] = umbral
    return resultado
