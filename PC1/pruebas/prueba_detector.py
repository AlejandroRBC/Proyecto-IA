"""Pruebas del detector con un IsolationForest de juguete (no usa el modelo real)."""

import json

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest

from src.modelo.detector import (
    ANOMALO,
    NO_EVALUABLE,
    NORMAL,
    cargar_detector,
    evaluar_flujo,
    evaluar_lote,
    preparar_flujo_para_prediccion,
)

COLUMNAS = [f"car_{i}" for i in range(10)]


@pytest.fixture(scope="module")
def detector():
    rng = np.random.default_rng(0)
    X = rng.normal(0, 1, size=(500, 10))
    modelo = IsolationForest(n_estimators=50, random_state=0).fit(X)
    umbral = float(np.percentile(modelo.decision_function(X), 1))
    return {"modelo": modelo, "metadatos": {}, "orden_columnas": COLUMNAS, "umbral": umbral}


def flujo(valor=0.0, **cambios):
    datos = {c: valor for c in COLUMNAS}
    datos.update(cambios)
    return datos


def prueba_flujo_valido_devuelve_resultado(detector):
    res = evaluar_flujo(detector, flujo(0.0))
    assert res["resultado"] in {NORMAL, ANOMALO}
    assert isinstance(res["score"], float)
    assert res["umbral"] == detector["umbral"]


def prueba_flujo_central_normal_y_extremo_anomalo(detector):
    assert evaluar_flujo(detector, flujo(0.0))["resultado"] == NORMAL
    assert evaluar_flujo(detector, flujo(50.0))["resultado"] == ANOMALO


def prueba_acepta_flujo_preparado_y_series(detector):
    preparado = preparar_flujo_para_prediccion(flujo(0.1), COLUMNAS)
    assert list(preparado.columns) == COLUMNAS
    assert evaluar_flujo(detector, preparado) == evaluar_flujo(detector, pd.Series(flujo(0.1)))


@pytest.mark.parametrize("invalido", [
    {"car_3": np.inf},
    {"car_3": -np.inf},
    {"car_3": np.nan},
    {"car_3": "Infinity"},
    {"car_3": "abc"},
])
def prueba_valor_invalido_no_se_evalua(detector, invalido):
    assert preparar_flujo_para_prediccion(flujo(0.0, **invalido), COLUMNAS) is None
    res = evaluar_flujo(detector, flujo(0.0, **invalido))
    assert res["resultado"] == NO_EVALUABLE
    assert res["score"] is None


def prueba_caracteristica_faltante_no_se_evalua(detector):
    datos = flujo(0.0)
    del datos["car_7"]
    assert preparar_flujo_para_prediccion(datos, COLUMNAS) is None
    assert evaluar_flujo(detector, datos)["resultado"] == NO_EVALUABLE
    assert evaluar_flujo(detector, None)["resultado"] == NO_EVALUABLE


def prueba_no_elimina_duplicados_y_limpia_nombres(detector):
    # Nombres con espacios como en CICIDS2017; dos filas idénticas se evalúan ambas.
    df = pd.DataFrame([flujo(0.0), flujo(0.0)])
    df.columns = [f" {c}" for c in df.columns]
    df["id_flujo"] = ["a", "b"]
    res = evaluar_lote(detector, df)
    assert len(res) == 2
    assert res["id_flujo"].tolist() == ["a", "b"]


def prueba_evaluar_lote_coincide_con_evaluar_flujo(detector):
    filas = [flujo(0.0), flujo(50.0), flujo(0.0, car_2=np.inf), flujo(0.3)]
    df = pd.DataFrame(filas)
    df["ip_origen"] = ["10.0.0.1", None, None, "10.0.0.4"]
    res = evaluar_lote(detector, df)

    assert {"resultado", "score", "ip_origen"} <= set(res.columns)
    for i, datos in enumerate(filas):
        individual = evaluar_flujo(detector, datos)
        assert res["resultado"].iloc[i] == individual["resultado"]
        if individual["score"] is None:
            assert pd.isna(res["score"].iloc[i])
        else:
            assert res["score"].iloc[i] == pytest.approx(individual["score"])


def prueba_cargar_detector_desde_archivos(detector, tmp_path):
    joblib.dump(detector["modelo"], tmp_path / "m.joblib")
    meta = {
        "caracteristicas": COLUMNAS,
        "orden_columnas": {c: i for i, c in enumerate(COLUMNAS)},
        "umbral": {"valor": detector["umbral"]},
    }
    (tmp_path / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    config = {
        "rutas": {"modelos": tmp_path},
        "archivos_salida": {"modelo": "m.joblib", "metadatos": "meta.json"},
    }
    cargado = cargar_detector(config)
    assert cargado["orden_columnas"] == COLUMNAS
    assert cargado["umbral"] == pytest.approx(detector["umbral"])
    assert evaluar_flujo(cargado, flujo(0.0))["resultado"] == NORMAL
