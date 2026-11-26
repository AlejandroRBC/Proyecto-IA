"""Random Forest multiclase que nombra la familia de ataque de un flujo (CICIDS2017).

Usa las mismas 10 características que Isolation Forest, pero es **supervisado**:
aprende de los flujos etiquetados de los 8 CSV. Las etiquetas se agrupan en familias
para tener clases con suficientes ejemplos. Infiltration (36 flujos) y Heartbleed (11)
quedan fuera: son demasiado pocos para aprender algo fiable.

En vivo solo se consulta para los flujos que Isolation Forest marcó ANOMALO y que
ninguna regla por ventana explica. Las reglas tienen prioridad porque están medidas en
el laboratorio; el Random Forest aprendió de otra red (cambio de dominio).
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

BENIGN = "BENIGN"
FAMILIAS = ["BENIGN", "DoS", "DDoS", "PortScan", "Fuerza bruta", "Ataque web", "Bot"]
NOMBRE_MODELO = "random_forest_ataques.joblib"
NOMBRE_METADATOS = "metadatos_clasificador.json"


def familia(etiqueta: str) -> str | None:
    """Etiqueta original de CICIDS2017 → familia (``None`` = se excluye)."""
    e = str(etiqueta).strip()
    if e == "BENIGN":
        return BENIGN
    if e.startswith("DoS"):
        return "DoS"
    if e == "DDoS":
        return "DDoS"
    if e == "PortScan":
        return "PortScan"
    if e in ("FTP-Patator", "SSH-Patator"):
        return "Fuerza bruta"
    if e.startswith("Web Attack"):
        return "Ataque web"
    if e == "Bot":
        return "Bot"
    return None  # Infiltration, Heartbleed


def rutas_clasificador(config: dict) -> tuple[Path, Path]:
    carpeta = Path(config["rutas"]["modelos_clasificador"])
    return carpeta / NOMBRE_MODELO, carpeta / NOMBRE_METADATOS


def cargar_clasificador(config: dict) -> dict | None:
    """Modelo + metadatos, o ``None`` si todavía no se entrenó (la captura sigue sin él)."""
    ruta_modelo, ruta_meta = rutas_clasificador(config)
    if not ruta_modelo.exists() or not ruta_meta.exists():
        return None
    with open(ruta_meta, encoding="utf-8") as f:
        metadatos = json.load(f)
    return {"modelo": joblib.load(ruta_modelo), "caracteristicas": metadatos["caracteristicas"],
            "metadatos": metadatos}


def predecir_familias(clasificador: dict, filas: list[dict] | pd.DataFrame) -> list[tuple[str, float] | None]:
    """(familia, probabilidad) por fila; ``None`` si falta algún valor o es infinito."""
    df = pd.DataFrame(filas) if not isinstance(filas, pd.DataFrame) else filas
    if df.empty:
        return []
    columnas = clasificador["caracteristicas"]
    x = df.reindex(columns=columnas).apply(pd.to_numeric, errors="coerce").astype("float64")
    validas = np.isfinite(x.to_numpy()).all(axis=1)
    salida: list[tuple[str, float] | None] = [None] * len(df)
    if validas.any():
        modelo = clasificador["modelo"]
        proba = modelo.predict_proba(x[validas])
        clases = modelo.classes_
        for pos, fila_proba in zip(np.flatnonzero(validas), proba):
            k = int(np.argmax(fila_proba))
            salida[pos] = (str(clases[k]), float(fila_proba[k]))
    return salida
