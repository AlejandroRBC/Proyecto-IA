"""Modelo de laboratorio: Isolation Forest entrenado con tráfico normal capturado en el laboratorio.

Misma metodología que el modelo base, pero con datos propios:

1. Los flujos capturados (``flujos_capturados.csv`` de ``capturar_en_vivo.py``) se
   etiquetan cruzándolos con el registro de escenarios de PC2: un flujo es
   ``escaneo_puertos`` o ``rafaga_conexiones`` si involucra la IP de PC2 de ese
   escenario y se solapa con su intervalo (más una tolerancia por desfase de relojes).
   Todo lo demás es ``normal``.
2. Se entrena SOLO con los flujos normales (80 %), con las mismas 10 características,
   los mismos hiperparámetros y la misma semilla.
3. El umbral se calibra con el 20 % de validación normal (FPR objetivo 1 %).
4. Se evalúa una sola vez sobre validación normal + todos los ataques. Los ataques
   nunca se usan para entrenar ni para elegir el umbral.

Las etiquetas solo sirven para separar entrenamiento/evaluación y medir; el modelo
nunca las recibe.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split

from src.modelo.entrenar import calibrar_umbral
from src.modelo.evaluar import calcular_metricas, metricas_por_tipo
from src.procesamiento.caracteristicas import limpiar

ETIQUETA = "etiqueta_laboratorio"
NORMAL = "normal"


class ErrorDatosLaboratorio(ValueError):
    """Datos insuficientes o mal formados para el modelo de laboratorio."""


def cargar_flujos_capturados(rutas: list[str | Path], caracteristicas: list[str]) -> pd.DataFrame:
    """Une uno o varios ``flujos_capturados.csv`` y descarta flujos repetidos entre archivos."""
    partes = []
    for ruta in rutas:
        ruta = Path(ruta)
        if not ruta.exists():
            raise ErrorDatosLaboratorio(f"No existe el archivo de flujos capturados: {ruta}")
        df = pd.read_csv(ruta, encoding="utf-8")
        faltantes = [c for c in [*caracteristicas, "id_flujo", "ip_origen", "ip_destino",
                                 "inicio_flujo", "fin_flujo"] if c not in df.columns]
        if faltantes:
            raise ErrorDatosLaboratorio(f"A {ruta.name} le faltan columnas: {faltantes}")
        df["archivo_captura"] = ruta.name
        partes.append(df)
    if not partes:
        raise ErrorDatosLaboratorio("No se indicó ningún archivo de flujos capturados.")
    flujos = pd.concat(partes, ignore_index=True).drop_duplicates(subset="id_flujo", keep="first")
    flujos["inicio_flujo"] = pd.to_datetime(flujos["inicio_flujo"], errors="coerce", format="ISO8601")
    flujos["fin_flujo"] = pd.to_datetime(flujos["fin_flujo"], errors="coerce", format="ISO8601")
    return flujos.dropna(subset=["inicio_flujo", "fin_flujo"]).reset_index(drop=True)


def cargar_escenarios_pc2(ruta: str | Path | None) -> pd.DataFrame:
    """Lee el CSV de escenarios de PC2. Sin archivo devuelve una tabla vacía."""
    columnas = ["fecha_hora_inicio", "fecha_hora_fin", "tipo_escenario", "ip_destino", "ip_origen"]
    if ruta is None or not Path(ruta).exists():
        return pd.DataFrame(columns=columnas)
    esc = pd.read_csv(ruta, encoding="utf-8", dtype=str).fillna("")
    if "ip_origen" not in esc.columns:      # CSV de una versión anterior de PC2
        esc["ip_origen"] = ""
    esc["fecha_hora_inicio"] = pd.to_datetime(esc["fecha_hora_inicio"], errors="coerce")
    esc["fecha_hora_fin"] = pd.to_datetime(esc["fecha_hora_fin"], errors="coerce")
    return esc.dropna(subset=["fecha_hora_inicio", "fecha_hora_fin"]).reset_index(drop=True)


def etiquetar_flujos(
    flujos: pd.DataFrame,
    escenarios: pd.DataFrame,
    tipos_ataque: list[str],
    tolerancia_segundos: float,
    ip_pc2_por_defecto: str | None = None,
) -> pd.Series:
    """Etiqueta cada flujo como ``normal`` o con el tipo de escenario de ataque que lo generó.

    Cada flujo que involucra la IP de PC2 se asigna al escenario (normal o de
    ataque) más cercano en el tiempo: distancia 0 si se solapa con él y, si no,
    los segundos que lo separan. Solo cuenta si esa distancia es como mucho
    ``tolerancia_segundos``. Así, un ping o una descarga ejecutados justo antes
    o después de una ráfaga no se confunden con ella. Con empate gana el
    escenario con más solapamiento. La etiqueta es el tipo del escenario si es
    de ataque y ``normal`` en cualquier otro caso.

    La IP de PC2 sale de la columna ``ip_origen`` del escenario; si está vacía
    (CSV antiguo), se usa ``ip_pc2_por_defecto``.
    """
    etiquetas = pd.Series(NORMAL, index=flujos.index, dtype=object)
    mejor_distancia = pd.Series(np.inf, index=flujos.index)
    mejor_solape = pd.Series(-np.inf, index=flujos.index)
    ips = flujos[["ip_origen", "ip_destino"]].astype(str)
    for _, esc in escenarios.iterrows():
        es_ataque = esc["tipo_escenario"] in tipos_ataque
        ip_pc2 = str(esc.get("ip_origen") or "").strip() or ip_pc2_por_defecto
        if not ip_pc2:
            if not es_ataque:
                continue  # un escenario normal sin IP no puede reclamar flujos; no es grave
            raise ErrorDatosLaboratorio(
                "Un escenario de ataque de PC2 no trae ip_origen (CSV de una versión anterior): "
                "indica la IP que tenía PC2 con --ip-pc2.")
        involucra = (ips["ip_origen"] == ip_pc2) | (ips["ip_destino"] == ip_pc2)
        antes = (esc["fecha_hora_inicio"] - flujos["fin_flujo"]).dt.total_seconds()
        despues = (flujos["inicio_flujo"] - esc["fecha_hora_fin"]).dt.total_seconds()
        distancia = np.maximum(0, np.maximum(antes, despues))
        solape = (np.minimum(flujos["fin_flujo"], esc["fecha_hora_fin"])
                  - np.maximum(flujos["inicio_flujo"], esc["fecha_hora_inicio"])).dt.total_seconds()
        gana = involucra & (distancia <= float(tolerancia_segundos)) & (
            (distancia < mejor_distancia) | ((distancia == mejor_distancia) & (solape > mejor_solape)))
        etiquetas[gana] = esc["tipo_escenario"] if es_ataque else NORMAL
        mejor_distancia[gana] = distancia[gana]
        mejor_solape[gana] = solape[gana]
    return etiquetas


def entrenar_y_evaluar(
    config: dict,
    flujos: pd.DataFrame,
    etiquetas: pd.Series,
    detector_base: dict | None = None,
) -> dict:
    """Entrena con los normales, calibra el umbral y evalúa. No guarda nada en disco."""
    caracteristicas = list(config["caracteristicas"])
    semilla = config["division"]["semilla"]
    minimo = int(config.get("laboratorio", {}).get("min_flujos_normales", 200))

    datos = flujos.assign(**{ETIQUETA: etiquetas.to_numpy()})
    print(f"  Flujos capturados: {len(datos):,}")
    datos = limpiar(datos, caracteristicas, ETIQUETA)
    normales = datos[datos[ETIQUETA] == NORMAL]
    ataques = datos[datos[ETIQUETA] != NORMAL]
    print(f"  Tras limpiar: {len(normales):,} normales | {len(ataques):,} de ataque "
          f"({', '.join(f'{k}={v:,}' for k, v in ataques[ETIQUETA].value_counts().items()) or 'ninguno'})")
    if len(normales) < minimo:
        raise ErrorDatosLaboratorio(
            f"Solo hay {len(normales)} flujos normales evaluables y se necesitan al menos {minimo}. "
            "Captura más tráfico normal (p. ej. 15-20 min con --todo-el-trafico).")

    ent, val = train_test_split(normales, test_size=config["division"]["proporcion_validacion"],
                                random_state=semilla)
    hiper = dict(config["modelo"])
    # Con pocos datos, max_samples no puede superar el número de filas de entrenamiento.
    if isinstance(hiper.get("max_samples"), int):
        hiper["max_samples"] = min(hiper["max_samples"], len(ent))
    modelo = IsolationForest(**hiper).fit(ent[caracteristicas].to_numpy())

    puntajes_val = modelo.decision_function(val[caracteristicas].to_numpy())
    fpr_objetivo = config["umbral"]["fpr_objetivo_validacion"]
    umbral = calibrar_umbral(puntajes_val, fpr_objetivo)
    print(f"  Entrenamiento: {len(ent):,} | Validación: {len(val):,} | umbral = {umbral:.6f}")

    # Conjunto de evaluación: validación normal (nunca vista al entrenar) + todos los ataques.
    evaluacion = pd.concat([val, ataques])
    X_eval = evaluacion[caracteristicas].to_numpy()
    y_real = (evaluacion[ETIQUETA] != NORMAL).astype(int).to_numpy()

    resultados = {}
    candidatos = {"laboratorio": (modelo, umbral)}
    if detector_base is not None:
        candidatos["base"] = (detector_base["modelo"], detector_base["umbral"])
    filas_metricas, filas_tipo = [], []
    for nombre, (mod, umb) in candidatos.items():
        puntajes = mod.decision_function(X_eval)
        y_pred = (puntajes < umb).astype(int)
        metricas = calcular_metricas(y_real, y_pred)
        metricas["roc_auc"] = (float(roc_auc_score(y_real, -puntajes))
                               if len(np.unique(y_real)) == 2 else float("nan"))
        metricas["umbral"] = float(umb)
        filas_metricas.append({"modelo": nombre, **metricas})
        por_tipo = metricas_por_tipo(evaluacion[ETIQUETA].rename("Label"), y_pred)
        filas_tipo.append(por_tipo.assign(modelo=nombre))
        resultados[nombre] = metricas

    return {
        "modelo": modelo,
        "umbral": umbral,
        "hiperparametros": hiper,
        "fpr_real_validacion": float(np.mean(puntajes_val < umbral)),
        "filas_entrenamiento": int(len(ent)),
        "filas_validacion": int(len(val)),
        "conteo_etiquetas": {k: int(v) for k, v in datos[ETIQUETA].value_counts().items()},
        "metricas": pd.DataFrame(filas_metricas),
        "metricas_por_tipo": pd.concat(filas_tipo, ignore_index=True)[
            ["modelo", "Label", "flujos", "detectados_como_anomalos", "proporcion_detectada"]],
        "resultados": resultados,
    }
