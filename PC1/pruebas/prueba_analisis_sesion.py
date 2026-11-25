"""Pruebas del análisis de sesiones (scripts/analizar_sesion.py) con flujos sintéticos."""

import matplotlib.pyplot as plt
import pandas as pd

from src.analisis.sesion import (
    asignar_tramos,
    cargar_sesion,
    clasificar_trafico,
    figura_sesion,
    metricas_globales,
    resumir,
)

PC1, PC2 = "192.168.1.7", "192.168.1.10"


def flujo(seg, origen, destino, sport, dport, proto, fwd, bwd, resultado, score):
    return {"inicio_flujo": f"2026-11-25T16:40:{seg:02d}.000", "ip_origen": origen, "ip_destino": destino,
            "puerto_origen": sport, "Destination Port": dport, "protocolo": proto,
            "Total Length of Fwd Packets": fwd, "Total Length of Bwd Packets": bwd,
            "resultado": resultado, "score": score, "umbral": -0.157}


def sesion():
    return pd.DataFrame([
        flujo(1, PC2, PC1, 50000, 8000, "TCP", 130, 203, "NORMAL", 0.02),            # descarga pequeña
        flujo(2, PC2, PC1, 50001, 8000, "TCP", 130, 262000, "ANOMALO", -0.21),       # descarga grande
        flujo(3, PC2, PC1, 50002, 8000, "TCP", 130, 93000, "ANOMALO", -0.20),        # grande incompleta
        flujo(4, PC1, PC2, 8000, 50003, "TCP", 241000, 0, "ANOMALO", -0.20),         # grande al revés
        flujo(5, PC2, PC1, 50004, 8080, "TCP", 0, 0, "NORMAL", 0.04),                # ráfaga
        flujo(6, PC1, PC2, 8080, 50005, "TCP", 0, 0, "NORMAL", 0.14),                # ráfaga al revés
        flujo(7, PC2, PC1, 0, 0, "ICMP", 320, 320, "NORMAL", -0.05),                 # ping
        flujo(8, PC2, "239.255.255.250", 60000, 1900, "UDP", 680, 0, "NORMAL", 0.14),  # SSDP
        flujo(9, "8.8.8.8", PC1, 443, 50010, "TCP", 10, 10, "ANOMALO", -0.3),        # no es de PC2
    ])


def prueba_clasifica_por_forma_incluidos_flujos_al_reves():
    df = sesion()
    assert clasificar_trafico(df).tolist() == [
        "descarga pequeña", "descarga grande", "descarga grande", "descarga grande",
        "ráfaga", "ráfaga", "ping", "otro", "otro"]


def prueba_cargar_sesion_filtra_pc2_y_fechas(tmp_path):
    ruta = tmp_path / "flujos.csv"
    sesion().to_csv(ruta, index=False)
    assert len(cargar_sesion(ruta, PC2)) == 8                                  # sin el flujo de 8.8.8.8
    assert len(cargar_sesion(ruta, PC2, desde="2026-11-25 16:40:05")) == 4
    assert len(cargar_sesion(ruta, PC2, hasta="2026-11-25 16:40:02")) == 2


def prueba_resumen_y_metricas():
    df = sesion().iloc[:8].copy()
    df["inicio"] = pd.to_datetime(df["inicio_flujo"])
    df["tipo_trafico"] = clasificar_trafico(df)
    tabla = resumir(df, "tipo_trafico").set_index("tipo_trafico")
    assert tabla.loc["descarga grande", "flujos"] == 3 and tabla.loc["descarga grande", "proporcion_anomala"] == 1
    assert list(tabla.index) == ["descarga pequeña", "ping", "otro", "descarga grande", "ráfaga"]
    m = metricas_globales(df)
    assert (m["verdaderos_positivos"], m["falsos_positivos"], m["falsos_negativos"], m["verdaderos_negativos"]) == (3, 0, 2, 3)
    assert m["recall_descargas_grandes"] == 1.0 and m["fpr_descargas_pequenas"] == 0.0 and m["precision"] == 1.0


def prueba_tramos_de_pc2_y_figura():
    df = sesion().iloc[:8].copy()
    df["inicio"] = pd.to_datetime(df["inicio_flujo"])
    df["tipo_trafico"] = clasificar_trafico(df)
    escenarios = pd.DataFrame({
        "fecha_hora_inicio": ["2026-11-25 16:40:00.000", "2026-11-25 16:40:02.000"],
        "fecha_hora_fin": ["2026-11-25 16:40:01.900", "2026-11-25 16:40:06.000"],
        "tipo_escenario": ["mixto_normal", "mixto_anomalo"]})
    df["tramo_pc2"] = asignar_tramos(df, escenarios)
    assert df["tramo_pc2"].tolist() == ["mixto_normal"] + ["mixto_anomalo"] * 5 + ["", ""]
    assert asignar_tramos(df, None).eq("").all()
    fig = figura_sesion(df, -0.157, escenarios)
    assert fig.axes
    plt.close(fig)
