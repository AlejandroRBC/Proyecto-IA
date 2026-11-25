"""Pruebas del modelo de laboratorio con flujos sintéticos (sin red ni dataset)."""

from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import pytest

from src.app import datos_panel as dp
from src.modelo.detector import cargar_detector, rutas_modelo
from src.modelo.laboratorio import (
    NORMAL,
    ErrorDatosLaboratorio,
    cargar_escenarios_pc2,
    cargar_flujos_capturados,
    entrenar_y_evaluar,
    etiquetar_flujos,
)

CARACTERISTICAS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "SYN Flag Count", "Destination Port",
]
PC1, PC2, OTRA = "192.168.1.7", "192.168.1.10", "142.250.0.1"
T0 = datetime(2026, 11, 25, 16, 0, 0)
TIPOS = ["escaneo_puertos", "rafaga_conexiones"]


def config_prueba(minimo=50):
    return {
        "caracteristicas": CARACTERISTICAS,
        "division": {"proporcion_validacion": 0.2, "semilla": 42},
        "modelo": {"n_estimators": 50, "max_samples": 256, "max_features": 1.0,
                   "contamination": "auto", "random_state": 42},
        "umbral": {"fpr_objetivo_validacion": 0.01},
        "laboratorio": {"min_flujos_normales": minimo},
    }


def flujo(i, segundo, ip_origen, ip_destino, valores):
    inicio = T0 + timedelta(seconds=segundo)
    return {"id_flujo": f"f{i}", "ip_origen": ip_origen, "ip_destino": ip_destino,
            "inicio_flujo": inicio.isoformat(), "fin_flujo": (inicio + timedelta(seconds=0.5)).isoformat(),
            **dict(zip(CARACTERISTICAS, valores))}


def flujos_sinteticos(n_normales=400, n_rafaga=60):
    """Normales: navegación con carga útil y duraciones variadas. Ráfaga: conexiones vacías y cortas."""
    rng = np.random.default_rng(0)
    filas = []
    for i in range(n_normales):
        dur = rng.uniform(5e4, 5e6)
        fwd, bwd = rng.integers(5, 40), rng.integers(5, 120)
        bf, bb = rng.integers(200, 3000), rng.integers(2000, 200000)
        valores = [dur, fwd, bwd, bf, bb, (bf + bb) / dur * 1e6, (fwd + bwd) / dur * 1e6,
                   dur / (fwd + bwd), 2, rng.choice([443, 80, 53])]
        filas.append(flujo(i, i % 50, PC1, OTRA, valores))
    for j in range(n_rafaga):  # ráfaga de PC2 entre los segundos 100 y 130
        dur = rng.uniform(800, 1500)
        valores = [dur, 4, 3, 0, 0, 0.0, 7 / dur * 1e6, dur / 6, 2, 8080]
        filas.append(flujo(n_normales + j, 100 + j * 0.5, PC2, PC1, valores))
    return pd.DataFrame(filas)


def escenarios(ip_origen=PC2):
    return pd.DataFrame({
        "fecha_hora_inicio": [T0 + timedelta(seconds=90), T0 + timedelta(seconds=100)],
        "fecha_hora_fin": [T0 + timedelta(seconds=95), T0 + timedelta(seconds=130)],
        "tipo_escenario": ["trafico_normal_ping", "rafaga_conexiones"],
        "ip_destino": [PC1, PC1],
        "ip_origen": [ip_origen, ip_origen],
    })


def con_fechas(df):
    df = df.copy()
    df["inicio_flujo"] = pd.to_datetime(df["inicio_flujo"], format="ISO8601")
    df["fin_flujo"] = pd.to_datetime(df["fin_flujo"], format="ISO8601")
    return df


# ---------- Etiquetado ----------

def prueba_etiqueta_solo_flujos_de_pc2_dentro_del_escenario_de_ataque():
    flujos = con_fechas(pd.DataFrame([
        flujo(1, 110, PC2, PC1, [0] * 10),     # dentro de la ráfaga, de PC2 → ataque
        flujo(2, 110, PC1, OTRA, [0] * 10),    # dentro de la ráfaga, pero no es PC2 → normal
        flujo(3, 92, PC2, PC1, [0] * 10),      # durante el ping (escenario normal) → normal
        flujo(4, 133, PC2, PC1, [0] * 10),     # 3 s después del fin: entra por la tolerancia
        flujo(5, 200, PC2, PC1, [0] * 10),     # mucho después → normal
    ]))
    etiquetas = etiquetar_flujos(flujos, escenarios(), TIPOS, tolerancia_segundos=5)
    assert etiquetas.tolist() == ["rafaga_conexiones", NORMAL, NORMAL, "rafaga_conexiones", NORMAL]
    assert etiquetar_flujos(flujos, escenarios(), TIPOS, 0).tolist()[3] == NORMAL


def prueba_ping_pegado_a_la_rafaga_no_se_etiqueta_como_ataque():
    """El ping termina en el segundo 95 y la ráfaga empieza en el 100: con tolerancia de 5 s
    un flujo del ping cae en la ventana de ambos y debe quedarse con el más cercano (el ping)."""
    esc = escenarios()
    esc.loc[1, "fecha_hora_inicio"] = T0 + timedelta(seconds=96)
    flujos = con_fechas(pd.DataFrame([
        flujo(1, 94, PC2, PC1, [0] * 10),     # termina en 94.5: dentro del ping
        flujo(2, 97, PC2, PC1, [0] * 10),     # dentro de la ráfaga
    ]))
    assert etiquetar_flujos(flujos, esc, TIPOS, 5).tolist() == [NORMAL, "rafaga_conexiones"]


def prueba_csv_antiguo_sin_ip_usa_ip_por_defecto_o_falla():
    flujos = con_fechas(pd.DataFrame([flujo(1, 110, PC2, PC1, [0] * 10)]))
    sin_ip = escenarios(ip_origen="")
    with pytest.raises(ErrorDatosLaboratorio, match="--ip-pc2"):
        etiquetar_flujos(flujos, sin_ip, TIPOS, 5)
    assert etiquetar_flujos(flujos, sin_ip, TIPOS, 5, PC2).tolist() == ["rafaga_conexiones"]


def prueba_cargar_archivos(tmp_path):
    df = flujos_sinteticos(20, 5)
    df.to_csv(tmp_path / "a.csv", index=False)
    df.head(10).to_csv(tmp_path / "b.csv", index=False)        # repetidos entre archivos
    cargados = cargar_flujos_capturados([tmp_path / "a.csv", tmp_path / "b.csv"], CARACTERISTICAS)
    assert len(cargados) == 25
    with pytest.raises(ErrorDatosLaboratorio):
        cargar_flujos_capturados([tmp_path / "no_existe.csv"], CARACTERISTICAS)

    ruta = tmp_path / "escenarios.csv"
    ruta.write_text("fecha_hora_inicio,fecha_hora_fin,tipo_escenario,parametros,ip_destino\n"
                    "2026-11-25 16:01:40,2026-11-25 16:02:10,rafaga_conexiones,{},192.168.1.7\n",
                    encoding="utf-8")
    esc = cargar_escenarios_pc2(ruta)
    assert esc.loc[0, "ip_origen"] == "" and esc.loc[0, "fecha_hora_fin"] == pd.Timestamp("2026-11-25 16:02:10")
    assert cargar_escenarios_pc2(None).empty


# ---------- Entrenamiento y evaluación ----------

def prueba_entrena_solo_con_normales_y_detecta_la_rafaga_sintetica():
    flujos = con_fechas(flujos_sinteticos())
    etiquetas = etiquetar_flujos(flujos, escenarios(), TIPOS, 5)
    res = entrenar_y_evaluar(config_prueba(), flujos, etiquetas)

    assert res["conteo_etiquetas"] == {NORMAL: 400, "rafaga_conexiones": 60}
    assert res["filas_entrenamiento"] == 320 and res["filas_validacion"] == 80
    assert res["hiperparametros"]["max_samples"] == 256
    por_tipo = res["metricas_por_tipo"].set_index("Label")
    assert por_tipo.loc["rafaga_conexiones", "proporcion_detectada"] > 0.9
    assert por_tipo.loc[NORMAL, "flujos"] == 80                 # solo validación, nunca entrenamiento
    assert set(res["metricas"]["modelo"]) == {"laboratorio"}


def prueba_max_samples_se_ajusta_con_pocos_datos():
    flujos = con_fechas(flujos_sinteticos(n_normales=100, n_rafaga=5))
    res = entrenar_y_evaluar(config_prueba(minimo=50), flujos, etiquetar_flujos(flujos, escenarios(), TIPOS, 5))
    assert res["hiperparametros"]["max_samples"] == 80


def prueba_rechaza_entrenar_con_pocos_normales():
    flujos = con_fechas(flujos_sinteticos(n_normales=30, n_rafaga=5))
    with pytest.raises(ErrorDatosLaboratorio, match="al menos 200"):
        entrenar_y_evaluar(config_prueba(minimo=200), flujos, etiquetar_flujos(flujos, escenarios(), TIPOS, 5))


def prueba_compara_con_el_modelo_base():
    class SiempreNormal:
        def decision_function(self, X):
            return np.ones(len(X))

    flujos = con_fechas(flujos_sinteticos())
    res = entrenar_y_evaluar(config_prueba(), flujos, etiquetar_flujos(flujos, escenarios(), TIPOS, 5),
                             detector_base={"modelo": SiempreNormal(), "umbral": 0.0})
    assert res["resultados"]["base"]["recall"] == 0.0
    assert res["resultados"]["laboratorio"]["recall"] > 0.9
    tabla = dp.tabla_por_tipo_laboratorio(res["metricas_por_tipo"])
    assert list(tabla.columns) == ["Tipo", "Flujos", "base", "laboratorio"]
    assert list(dp.tabla_metricas_laboratorio(res["metricas"])["Modelo"]) == ["laboratorio", "base"]


# ---------- Detector y panel ----------

def prueba_detector_laboratorio_inexistente_explica_como_entrenarlo(tmp_path):
    config = {"rutas": {"modelos": tmp_path, "modelos_laboratorio": tmp_path / "laboratorio"},
              "archivos_salida": {"modelo": "m.joblib", "metadatos": "m.json",
                                  "modelo_laboratorio": "lab.joblib", "metadatos_laboratorio": "lab.json"}}
    assert rutas_modelo(config, "laboratorio")[0] == tmp_path / "laboratorio" / "lab.joblib"
    with pytest.raises(FileNotFoundError, match="entrenar_modelo_laboratorio"):
        cargar_detector(config, "laboratorio")
    with pytest.raises(ValueError):
        rutas_modelo(config, "otro")


def prueba_umbral_en_vivo_usa_el_del_flujo_mas_reciente():
    vivo = pd.DataFrame({"umbral": [-0.157, -0.157, -0.05]})
    assert dp.umbral_en_vivo(vivo, -0.157) == -0.05
    assert dp.umbral_en_vivo(pd.DataFrame({"score": [0.1]}), -0.157) == -0.157
