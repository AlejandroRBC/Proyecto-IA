"""Pruebas del parámetro aplicar_log1p de limpiar(), con datos sintéticos."""

import numpy as np
import pandas as pd
import pandas.testing as pdt

from src.procesamiento.caracteristicas import COLUMNAS_LOG1P, limpiar

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
SIN_TRANSFORMAR = ["Total Fwd Packets", "Total Backward Packets", "SYN Flag Count", "Destination Port"]


def datos_sinteticos():
    filas = []
    for i, valor in enumerate([0.0, 9.0, 99.0, 999.0]):
        fila = {c: valor for c in CARACTERISTICAS}
        fila["Destination Port"] = 80 + i
        fila["Label"] = "BENIGN"
        filas.append(fila)
    filas.append(dict(filas[1]))                                     # duplicado
    filas.append({**filas[2], "Flow Bytes/s": np.inf})               # infinito
    return pd.DataFrame(filas)


def prueba_sin_log1p_es_identico_al_comportamiento_actual():
    df = datos_sinteticos()
    por_defecto = limpiar(df, CARACTERISTICAS, "Label", verbose=False)
    explicito = limpiar(df, CARACTERISTICAS, "Label", verbose=False, aplicar_log1p=False)
    pdt.assert_frame_equal(por_defecto, explicito)
    assert len(por_defecto) == 4
    assert por_defecto["Flow Bytes/s"].tolist() == [0.0, 9.0, 99.0, 999.0]


def prueba_log1p_transforma_solo_volumen_y_tasa():
    df = datos_sinteticos()
    base = limpiar(df, CARACTERISTICAS, "Label", verbose=False)
    log = limpiar(df, CARACTERISTICAS, "Label", verbose=False, aplicar_log1p=True)

    assert len(log) == len(base)
    for c in COLUMNAS_LOG1P:
        np.testing.assert_allclose(log[c], np.log1p(base[c]))
    for c in SIN_TRANSFORMAR:
        pdt.assert_series_equal(log[c], base[c])
    assert list(log.columns) == CARACTERISTICAS + ["Label"]
    assert log.attrs["filas_negativas_eliminadas"] == 0


def prueba_duplicados_se_deciden_antes_de_log1p():
    # Ambos valores son válidos y distintos antes de la transformación: no son duplicados.
    a = {c: 1.0 for c in CARACTERISTICAS} | {"Label": "BENIGN"}
    b = a | {"Flow Bytes/s": 1.0000000001}
    log = limpiar(pd.DataFrame([a, b]), CARACTERISTICAS, "Label", verbose=False, aplicar_log1p=True)
    assert len(log) == 2


def prueba_negativos_se_eliminan_y_no_quedan_nan():
    df = datos_sinteticos()
    df.loc[0, "Flow Bytes/s"] = -5.0
    df.loc[3, "Flow IAT Mean"] = -1.0          # log1p(-1) sería -inf
    df.loc[2, "Total Fwd Packets"] = -3.0      # columna sin transformar: no se elimina por negativa

    log = limpiar(df, CARACTERISTICAS, "Label", verbose=False, aplicar_log1p=True)
    assert log.attrs["filas_negativas_eliminadas"] == 2
    assert len(log) == 2
    assert np.isfinite(log[CARACTERISTICAS].to_numpy()).all()
    assert log["Destination Port"].tolist() == [81, 82]
