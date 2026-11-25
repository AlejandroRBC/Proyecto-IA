"""Pruebas del gestor de alertas con un CSV temporal."""

import csv

from src.alertas.gestor_alertas import (
    COLUMNAS_ALERTA,
    COLUMNAS_HISTORIAL,
    procesar_resultado,
    registrar_alerta,
    registrar_flujo_analizado,
)


def leer(ruta):
    with open(ruta, encoding="utf-8", newline="") as f:
        return list(csv.reader(f))


def evaluado(resultado, id_flujo="f1"):
    return {"id_flujo": id_flujo, "resultado": resultado, "score": -0.2, "umbral": -0.15,
            "ip_origen": None, "ip_destino": None, "puerto_origen": None}


def prueba_solo_registra_anomalos(tmp_path):
    ruta = tmp_path / "alertas.csv"
    assert procesar_resultado(ruta, evaluado("NORMAL")) is False
    assert procesar_resultado(ruta, evaluado("NO_EVALUABLE")) is False
    assert not ruta.exists()

    assert procesar_resultado(ruta, evaluado("ANOMALO", "f2")) is True
    filas = leer(ruta)
    assert len(filas) == 2
    assert filas[1][COLUMNAS_ALERTA.index("id_flujo")] == "f2"
    assert filas[1][COLUMNAS_ALERTA.index("resultado")] == "ANOMALO"


def prueba_encabezado_una_sola_vez(tmp_path):
    ruta = tmp_path / "alertas.csv"
    for i in range(3):
        procesar_resultado(ruta, evaluado("ANOMALO", f"f{i}"))
        procesar_resultado(ruta, evaluado("NORMAL", f"n{i}"))
    filas = leer(ruta)
    assert filas[0] == COLUMNAS_ALERTA
    assert sum(f == COLUMNAS_ALERTA for f in filas) == 1
    assert [f[COLUMNAS_ALERTA.index("id_flujo")] for f in filas[1:]] == ["f0", "f1", "f2"]


def prueba_crea_carpeta_y_fecha_por_defecto(tmp_path):
    ruta = tmp_path / "no_existe" / "en_vivo" / "alertas.csv"
    registrar_alerta(ruta, {"resultado": "ANOMALO", "score": -0.3})
    filas = leer(ruta)
    assert filas[1][COLUMNAS_ALERTA.index("fecha_hora")] != ""
    assert filas[1][COLUMNAS_ALERTA.index("ip_origen")] == ""


def prueba_respeta_fecha_provista(tmp_path):
    ruta = tmp_path / "alertas.csv"
    registrar_alerta(ruta, {"fecha_hora": "2017-07-07T15:00:00", "resultado": "ANOMALO"})
    assert leer(ruta)[1][0] == "2017-07-07T15:00:00"


def prueba_historial_registra_normales_y_anomalos(tmp_path):
    # A diferencia de procesar_resultado, el historial guarda todos los resultados.
    alertas = tmp_path / "alertas.csv"
    historial = tmp_path / "en_vivo" / "flujos_analizados.csv"
    for res, id_flujo in [("NORMAL", "n1"), ("ANOMALO", "a1"), ("NORMAL", "n2"), ("NO_EVALUABLE", "x1")]:
        info = evaluado(res, id_flujo) | {"archivo_origen": "demo.csv", "puerto_destino": 80}
        procesar_resultado(alertas, info)
        registrar_flujo_analizado(historial, info)

    filas = leer(historial)
    assert filas[0] == COLUMNAS_HISTORIAL
    assert sum(f == COLUMNAS_HISTORIAL for f in filas) == 1
    assert [f[COLUMNAS_HISTORIAL.index("resultado")] for f in filas[1:]] == [
        "NORMAL", "ANOMALO", "NORMAL", "NO_EVALUABLE"]
    assert filas[1][COLUMNAS_HISTORIAL.index("archivo_origen")] == "demo.csv"
    assert filas[1][COLUMNAS_HISTORIAL.index("fecha_hora")] != ""
    # Las alertas siguen guardando solo la anomalía.
    assert [f[COLUMNAS_ALERTA.index("id_flujo")] for f in leer(alertas)[1:]] == ["a1"]
