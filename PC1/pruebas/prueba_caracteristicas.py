"""Pruebas de la limpieza de características con datos simulados en memoria."""

import numpy as np
import pandas as pd
import pytest

from src.procesamiento.caracteristicas import limpiar, seleccionar_caracteristicas
from src.procesamiento.dataset import ErrorColumnas

CARACTERISTICAS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "SYN Flag Count",
    "Destination Port",
]


def fila(valor, label="BENIGN", **cambios):
    """Crea una fila simulada con todas las características en ``valor``."""
    datos = {c: valor for c in CARACTERISTICAS}
    datos.update(cambios)
    datos["Label"] = label
    datos["Columna Extra"] = 999  # no debe llegar a la salida
    return datos


def prueba_elimina_infinitos_y_nan():
    df = pd.DataFrame([
        fila(1),
        fila(2, **{"Flow Bytes/s": np.inf}),
        fila(3, **{"Flow Packets/s": -np.inf}),
        fila(4, **{"Flow IAT Mean": np.nan}),
        fila(5, **{"Flow Bytes/s": "Infinity"}),  # texto, como en algunos CSV
        fila(6, **{"Destination Port": "abc"}),   # no numérico → NaN
    ])
    limpio = limpiar(df, CARACTERISTICAS, "Label", verbose=False)
    assert len(limpio) == 1
    assert limpio["Flow Duration"].iloc[0] == 1
    assert np.isfinite(limpio[CARACTERISTICAS].to_numpy()).all()


def prueba_duplicados_solo_sobre_caracteristicas():
    # Mismas 10 características, distinta columna extra y distinta etiqueta:
    # deben contarse como duplicados y quedarse solo la primera.
    a = fila(1)
    b = fila(1, label="DDoS")
    b["Columna Extra"] = 123
    c = fila(2)
    limpio = limpiar(pd.DataFrame([a, b, c]), CARACTERISTICAS, "Label", verbose=False)
    assert len(limpio) == 2
    assert limpio["Label"].tolist() == ["BENIGN", "BENIGN"]


def prueba_orden_fijo_de_columnas():
    df = pd.DataFrame([fila(1)])
    df = df[list(reversed(df.columns))]  # desordenar
    limpio = limpiar(df, CARACTERISTICAS, "Label", verbose=False)
    assert list(limpio.columns) == CARACTERISTICAS + ["Label"]


def prueba_sin_etiqueta():
    limpio = limpiar(pd.DataFrame([fila(1)]), CARACTERISTICAS, verbose=False)
    assert list(limpio.columns) == CARACTERISTICAS


def prueba_columna_faltante_lanza_error_claro():
    df = pd.DataFrame([fila(1)]).drop(columns=["SYN Flag Count"])
    with pytest.raises(ErrorColumnas, match="SYN Flag Count"):
        seleccionar_caracteristicas(df, CARACTERISTICAS, "Label")
    with pytest.raises(ErrorColumnas, match="SYN Flag Count"):
        limpiar(df, CARACTERISTICAS, "Label", verbose=False)
