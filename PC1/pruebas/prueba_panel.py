"""Pruebas de la lógica del panel (sin Streamlit ni el modelo real)."""

import sys

import matplotlib.pyplot as plt
import pandas as pd

from src.app import datos_panel as dp


def prueba_leer_csv_ausente_o_vacio_no_lanza(tmp_path):
    df, error = dp.leer_csv(tmp_path / "no_existe.csv")
    assert df is None and "No existe" in error
    (tmp_path / "vacio.csv").write_text("", encoding="utf-8")
    df, error = dp.leer_csv(tmp_path / "vacio.csv")
    assert df is None and error


def prueba_construir_comando():
    base = dp.construir_comando("Monday.csv", 50, 0.0, 42)
    assert base[0] == sys.executable
    assert base[base.index("--origen") + 1] == "Monday.csv"
    assert "--etiqueta" not in base
    assert "--etiqueta" not in dp.construir_comando("x.csv", 5, 0, 1, dp.TODAS_LAS_ETIQUETAS)
    con = dp.construir_comando("x.csv", 5, 0.05, 1, "Heartbleed")
    assert con[con.index("--etiqueta") + 1] == "Heartbleed"


def prueba_conteos_y_umbral_hipotetico():
    historial = pd.DataFrame({
        "score": [0.10, -0.20, 0.05, None, -0.30],
        "resultado": ["NORMAL", "ANOMALO", "NORMAL", "NO_EVALUABLE", "ANOMALO"],
    })
    assert dp.conteos(historial) == {"total": 5, "normales": 2, "anomalos": 2, "no_evaluables": 1}
    scores = dp.puntajes(historial)
    assert len(scores) == 4
    assert dp.contar_anomalos_con_umbral(scores, -0.157) == 2
    assert dp.contar_anomalos_con_umbral(scores, 0.07) == 3


def prueba_tabla_por_tipo_ordenada_por_recall():
    por_tipo = pd.DataFrame({
        "Label": ["BENIGN", "PortScan", "Heartbleed", "Infiltration"],
        "flujos": [1000, 90, 11, 36],
        "detectados_como_anomalos": [12, 0, 11, 12],
        "proporcion_detectada": [0.012, 0.0, 1.0, 0.333],
    })
    assert dp.tabla_por_tipo(por_tipo)["Label"].tolist() == ["Heartbleed", "Infiltration", "BENIGN", "PortScan"]


def prueba_borrar_historial(tmp_path):
    config = {"rutas": {"alertas": tmp_path / "a.csv", "flujos_analizados": tmp_path / "f.csv"}}
    (tmp_path / "a.csv").write_text("x", encoding="utf-8")
    assert dp.borrar_historial(config) == ["a.csv"]
    assert dp.borrar_historial(config) == []


def prueba_figura_se_genera():
    historial = pd.DataFrame({"score": [0.1, -0.2, None], "resultado": ["NORMAL", "ANOMALO", "NO_EVALUABLE"]})
    fig = dp.figura_puntajes(historial, -0.157, umbral_hipotetico=0.0)
    assert fig is not None
    plt.close(fig)
