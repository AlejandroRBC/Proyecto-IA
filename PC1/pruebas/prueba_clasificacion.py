"""Pruebas de la clasificación de ataques (reglas por ventana + Random Forest) con flujos sintéticos."""

from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import pytest

from src.alertas.gestor_alertas import registrar_incidente
from src.analisis.sesion import cruce_trafico_ataque, metricas_combinadas
from src.app import datos_panel as dp
from src.clasificacion.clasificador import ClasificadorAtaques
from src.clasificacion.modelo_ataques import familia, predecir_familias
from src.clasificacion.reglas import (
    COLUMNAS_INCIDENTE,
    ESCANEO,
    RAFAGA,
    SIN_CLASIFICAR,
    TRANSFERENCIA,
    ClasificadorVentana,
    clasificar_dataframe,
    describir_incidente,
    nombre_tipo,
    orientar,
)

PC1, PC2 = "192.168.1.7", "192.168.1.10"
T0 = datetime(2026, 11, 25, 16, 40, 0)


def flujo(seg, dport, sport=15000, origen=PC2, destino=PC1, proto="TCP", fwd=100, bwd=200,
          resultado="NORMAL", **extra):
    return {"inicio_flujo": (T0 + timedelta(seconds=seg)).isoformat(timespec="milliseconds"),
            "ip_origen": origen, "ip_destino": destino, "puerto_origen": sport, "puerto_destino": dport,
            "protocolo": proto, "Total Length of Fwd Packets": fwd, "Total Length of Bwd Packets": bwd,
            "resultado": resultado, **extra}


def normales(n=20):
    """Tráfico normal: una descarga pequeña cada 2 s y un ping."""
    return [flujo(2 * i, 8000, 15000 + i) for i in range(n)] + [flujo(5, 0, 0, proto="ICMP")]


# --- orientación de flujos -------------------------------------------------------------
def prueba_orientar_normal_y_al_reves():
    o = orientar(flujo(0, 8000, 15000, bwd=250_000))
    assert (o.atacante, o.victima, o.puerto, o.bytes_servidor, o.al_reves) == (PC2, PC1, 8000, 250_000, False)
    # SYN perdido: el flujo empieza con el servidor (PC1:8000) hacia el puerto del cliente.
    o = orientar(flujo(0, 14472, 8000, origen=PC1, destino=PC2, fwd=241_105, bwd=0))
    assert (o.atacante, o.victima, o.puerto, o.bytes_servidor, o.al_reves) == (PC2, PC1, 8000, 241_105, True)
    # Sondeo de nmap a un puerto alto desde un puerto efímero: NO está al revés.
    assert orientar(flujo(0, 49152, 15000)).al_reves is False


# --- reglas ------------------------------------------------------------------------------
def prueba_trafico_normal_no_genera_incidentes():
    c = ClasificadorVentana()
    filas, tocados, nuevos = c.procesar(normales())
    assert all(f["tipo_ataque"] == "" for f in filas)
    assert tocados == [] and nuevos == []


def prueba_escaneo_de_puertos():
    c = ClasificadorVentana()
    sondeos = [flujo(i * 0.1, 20 + i, 40000 + i, fwd=0, bwd=0) for i in range(30)]
    filas, _, nuevos = c.procesar(sondeos)
    assert [f["tipo_ataque"] for f in filas[:14]] == [""] * 14     # aún no hay 15 puertos
    assert all(f["tipo_ataque"] == ESCANEO for f in filas[14:])
    assert len(nuevos) == 1 and nuevos[0]["puertos_distintos"] == 16 and nuevos[0]["detectado_por"] == "reglas"


def prueba_rafaga_al_mismo_puerto_un_solo_incidente():
    c = ClasificadorVentana()
    rafaga = [flujo(i * 0.05, 8080, 13000 + i, fwd=0, bwd=0) for i in range(80)]
    filas, tocados, nuevos = c.procesar(rafaga)
    assert sum(f["tipo_ataque"] == RAFAGA for f in filas) == 31   # desde la conexión 50
    assert len(nuevos) == 1 and len(tocados) == 1
    assert tocados[0]["flujos"] == 31 and tocados[0]["conexiones_por_segundo"] == 8.0
    # Un segundo lote de la misma ráfaga actualiza el incidente, no abre otro.
    _, tocados2, nuevos2 = c.procesar([flujo(4 + i * 0.05, 8080, 14000 + i, fwd=0, bwd=0) for i in range(20)])
    assert nuevos2 == [] and tocados2[0]["id_incidente"] == tocados[0]["id_incidente"]
    assert tocados2[0]["flujos"] == 51


def prueba_incidente_nuevo_tras_inactividad():
    c = ClasificadorVentana({"inactividad_incidente_segundos": 30})
    c.procesar([flujo(0, 8000, bwd=250_000, resultado="ANOMALO")])
    _, _, nuevos = c.procesar([flujo(100, 8000, 15001, bwd=250_000, resultado="ANOMALO")])
    assert len(nuevos) == 1 and len(c.todos) == 2


def prueba_transferencia_masiva_por_modelo_y_por_volumen():
    c = ClasificadorVentana()
    filas, _, _ = c.procesar([flujo(0, 8000, bwd=250_000, resultado="ANOMALO")])
    assert filas[0]["tipo_ataque"] == TRANSFERENCIA
    # Descargas grandes que el modelo NO marcó, pero que suman más de 5 MB en la ventana.
    c = ClasificadorVentana()
    filas, _, nuevos = c.procesar([flujo(i * 0.2, 8000, 16000 + i, bwd=250_000) for i in range(25)])
    assert filas[0]["tipo_ataque"] == "" and filas[-1]["tipo_ataque"] == TRANSFERENCIA
    assert nuevos[0]["detectado_por"] == "reglas"


def prueba_descargas_rapidas_no_son_rafaga():
    """Muchas descargas grandes al mismo puerto no cuentan como ráfaga (no son conexiones cortas)."""
    c = ClasificadorVentana()
    filas, _, _ = c.procesar([flujo(i * 0.1, 8000, 16000 + i, bwd=250_000, resultado="ANOMALO")
                              for i in range(80)])
    assert {f["tipo_ataque"] for f in filas} == {TRANSFERENCIA}


def prueba_anomalo_sin_regla_y_familia_rf():
    c = ClasificadorVentana()
    filas, _, nuevos = c.procesar([flujo(0, 22, bwd=100, resultado="ANOMALO")])
    assert filas[0]["tipo_ataque"] == SIN_CLASIFICAR and nuevos[0]["detectado_por"] == "modelo"
    c = ClasificadorVentana()
    filas, _, nuevos = c.procesar([flujo(0, 22, bwd=100, resultado="ANOMALO", familia_rf="Fuerza bruta",
                                         prob_rf=0.9)])
    assert filas[0]["tipo_ataque"] == "rf:Fuerza bruta" and nuevos[0]["detectado_por"] == "modelo + random forest"
    assert nombre_tipo("rf:Fuerza bruta") == "Fuerza bruta (Random Forest)"
    # Probabilidad baja o BENIGN: se queda sin clasificar.
    for fam, prob in (("Fuerza bruta", 0.3), ("BENIGN", 0.99)):
        c = ClasificadorVentana()
        filas, _, _ = c.procesar([flujo(0, 22, resultado="ANOMALO", familia_rf=fam, prob_rf=prob)])
        assert filas[0]["tipo_ataque"] == SIN_CLASIFICAR


def prueba_clasificar_dataframe_y_describir():
    df = pd.DataFrame(normales() + [flujo(50 + i * 0.05, 8080, 13000 + i, fwd=0, bwd=0) for i in range(60)])
    salida, incidentes = clasificar_dataframe(df)
    assert (salida["tipo_ataque"] == RAFAGA).sum() == 11
    assert list(incidentes.columns) == COLUMNAS_INCIDENTE and len(incidentes) == 1
    assert "RÁFAGA" in describir_incidente(incidentes.iloc[0].to_dict())


# --- Random Forest -----------------------------------------------------------------------
def prueba_familias_de_cicids():
    assert familia("DoS Hulk") == "DoS" and familia("DDoS") == "DDoS" and familia("SSH-Patator") == "Fuerza bruta"
    assert familia("Web Attack \x96 XSS") == "Ataque web" and familia("BENIGN") == "BENIGN"
    assert familia("Heartbleed") is None and familia("Infiltration") is None


class _ModeloFalso:
    classes_ = np.array(["BENIGN", "DoS"])

    def predict_proba(self, x):
        return np.array([[0.2, 0.8] if v > 100 else [0.9, 0.1] for v in x["a"]])


def prueba_predecir_familias_ignora_invalidos():
    rf = {"modelo": _ModeloFalso(), "caracteristicas": ["a"]}
    pred = predecir_familias(rf, [{"a": 500}, {"a": float("inf")}, {"a": 5}, {}])
    assert pred[0] == ("DoS", pytest.approx(0.8)) and pred[1] is None and pred[2][0] == "BENIGN" and pred[3] is None


def prueba_clasificador_completo_usa_rf_solo_en_anomalos():
    rf = {"modelo": _ModeloFalso(), "caracteristicas": ["a"]}
    c = ClasificadorAtaques({"clasificacion": {}}, clasificador_rf=rf, usar_rf=True)
    filas = [flujo(0, 22, resultado="ANOMALO", a=500), flujo(1, 23, resultado="NORMAL", a=500)]
    tocados, nuevos = c.procesar(filas)
    assert filas[0]["familia_rf"] == "DoS" and filas[0]["tipo_ataque"] == "rf:DoS"
    assert filas[1]["familia_rf"] == "" and filas[1]["tipo_ataque"] == ""
    assert c.total_incidentes == 1 and c.conteo_por_tipo() == {"rf:DoS": 1}


# --- registro, panel y análisis --------------------------------------------------------------
def prueba_registro_y_vista_de_incidentes(tmp_path):
    c = ClasificadorVentana()
    ruta = tmp_path / "incidentes.csv"
    for lote in range(2):
        _, tocados, _ = c.procesar([flujo(lote * 3 + i * 0.05, 8080, 13000 + lote * 100 + i, fwd=0, bwd=0)
                                    for i in range(60)])
        for inc in tocados:
            registrar_incidente(ruta, inc)
    leido = pd.read_csv(ruta)
    assert len(leido) == 2                                   # dos actualizaciones del mismo incidente
    ultimos = dp.ultimos_incidentes(leido)
    assert len(ultimos) == 1 and dp.conteo_incidentes(ultimos)["rafaga_conexiones"] == 1
    assert dp.tabla_incidentes(ultimos)["Tipo de ataque"].iloc[0] == "Ráfaga de conexiones (DoS)"
    assert dp.ultimos_incidentes(None).empty


def prueba_metricas_combinadas_de_sesion():
    df = pd.DataFrame({
        "tipo_trafico": ["descarga pequeña", "descarga grande", "ráfaga", "ráfaga"],
        "resultado": ["NORMAL", "ANOMALO", "NORMAL", "NORMAL"],
        "tipo_ataque": ["", TRANSFERENCIA, RAFAGA, ""],
    })
    m = metricas_combinadas(df)
    assert (m["verdaderos_positivos"], m["falsos_positivos"], m["falsos_negativos"], m["verdaderos_negativos"]) == (2, 0, 1, 1)
    assert cruce_trafico_ataque(df)["tipo_trafico"].tolist() == ["descarga pequeña", "descarga grande", "ráfaga"]
