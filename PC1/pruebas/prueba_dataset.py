"""Pruebas de carga con CSV pequeños simulados (no se usan los datasets reales)."""

import pandas as pd
import pytest

from src.procesamiento.dataset import (
    ErrorColumnas,
    cargar_configuracion,
    cargar_csv,
    limpiar_nombres_columnas,
    verificar_columnas,
)


@pytest.fixture
def config(tmp_path):
    """Configuración real con la ruta de datos crudos apuntando a una carpeta temporal."""
    cfg = cargar_configuracion()
    cfg["rutas"]["datos_crudos"] = tmp_path
    return cfg


def escribir_csv(ruta, columnas, filas):
    """Escribe un CSV con espacios iniciales en los nombres, como CICIDS2017."""
    pd.DataFrame(filas, columns=[f" {c}" for c in columnas]).to_csv(ruta, index=False)


def prueba_configuracion_resuelve_rutas():
    cfg = cargar_configuracion()
    assert cfg["rutas"]["datos_crudos"].name == "Datasets"
    assert len(cfg["caracteristicas"]) == 10
    assert "Wednesday-workingHours.pcap_ISCX.csv" in cfg["datos"]["archivos_evaluacion"]


def prueba_limpiar_nombres_columnas():
    df = pd.DataFrame(columns=[" Flow Duration", "Label ", "  Destination Port"])
    assert list(limpiar_nombres_columnas(df).columns) == ["Flow Duration", "Label", "Destination Port"]


def prueba_carga_csv_solo_columnas_requeridas(config, tmp_path):
    columnas = config["caracteristicas"] + ["Otra Columna", "Label"]
    filas = [list(range(10)) + [7, " BENIGN"], list(range(1, 11)) + [8, "DDoS"]]
    escribir_csv(tmp_path / "simulado.csv", columnas, filas)

    df = cargar_csv(config, "simulado.csv")
    assert set(df.columns) == set(config["caracteristicas"] + ["Label"])
    assert df["Label"].tolist() == ["BENIGN", "DDoS"]  # etiqueta sin espacios


def prueba_columna_faltante_lanza_error_claro(config, tmp_path):
    columnas = [c for c in config["caracteristicas"] if c != "Flow IAT Mean"] + ["Label"]
    escribir_csv(tmp_path / "incompleto.csv", columnas, [list(range(9)) + ["BENIGN"]])

    with pytest.raises(ErrorColumnas, match="Flow IAT Mean"):
        cargar_csv(config, "incompleto.csv")
    with pytest.raises(ErrorColumnas, match="Flow IAT Mean"):
        verificar_columnas(config, "incompleto.csv")
