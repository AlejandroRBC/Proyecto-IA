"""Experimento aislado: Isolation Forest con log1p en las características de volumen y tasa.

No toca el modelo base ni sus reportes. Usa la misma división (semilla 42), los mismos
hiperparámetros y la misma calibración del umbral (1 % de FPR en su propia validación).
Evalúa UNA sola vez sobre los 7 archivos de evaluación; no se ajusta nada con esos resultados.

Uso (desde PC1/):  python scripts/experimento_log1p.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.modelo.entrenar import calibrar_umbral  # noqa: E402
from src.modelo.evaluar import calcular_metricas, guardar_histograma, metricas_por_tipo  # noqa: E402
from src.procesamiento.caracteristicas import COLUMNAS_LOG1P, limpiar  # noqa: E402
from src.procesamiento.dataset import (  # noqa: E402
    cargar_configuracion,
    cargar_entrenamiento,
    cargar_evaluacion,
)

MARCA_FIN_GENERADO = "<!-- fin de la parte generada por experimento_log1p.py -->"


def entrenar_log1p(config: dict) -> tuple[IsolationForest, dict]:
    caracteristicas = config["caracteristicas"]
    etiqueta = config["datos"]["columna_etiqueta"]
    semilla = config["division"]["semilla"]

    print("\n=== Entrenamiento (variante log1p) ===")
    df = limpiar(cargar_entrenamiento(config), caracteristicas, etiqueta, aplicar_log1p=True)
    negativos = df.attrs.get("filas_negativas_eliminadas", 0)
    df = df[df[etiqueta] == config["datos"]["valor_benigno"]]
    print(f"  Filas BENIGN disponibles: {len(df):,}")

    X_ent, X_val = train_test_split(
        df[caracteristicas].to_numpy(),
        test_size=config["division"]["proporcion_validacion"],
        random_state=semilla,
    )
    print(f"  Entrenamiento: {len(X_ent):,} filas | Validación: {len(X_val):,} filas")

    hiper = dict(config["modelo"])
    modelo = IsolationForest(**hiper).fit(X_ent)

    puntajes_val = modelo.decision_function(X_val)
    fpr_objetivo = config["umbral"]["fpr_objetivo_validacion"]
    umbral = calibrar_umbral(puntajes_val, fpr_objetivo)
    fpr_real = float(np.mean(puntajes_val < umbral))
    print(f"  Umbral calibrado: {umbral:.6f} | FPR real en validación: {fpr_real:.4%}")

    directorio = config["rutas"]["modelos_log1p"]
    directorio.mkdir(parents=True, exist_ok=True)
    metadatos = {
        "fecha_entrenamiento": datetime.now().isoformat(timespec="seconds"),
        "algoritmo": "IsolationForest",
        "variante": "log1p (experimento)",
        "version_scikit_learn": sklearn.__version__,
        "archivo_entrenamiento": config["datos"]["archivo_entrenamiento"],
        "caracteristicas": list(caracteristicas),
        "orden_columnas": {c: i for i, c in enumerate(caracteristicas)},
        "transformacion": {
            "tipo": "np.log1p",
            "columnas": [c for c in COLUMNAS_LOG1P if c in caracteristicas],
            "nota": "Se eliminan antes las filas con negativos en esas columnas. "
                    "El modelo espera las características ya transformadas.",
        },
        "hiperparametros": hiper,
        "division": {
            "proporcion_validacion": config["division"]["proporcion_validacion"],
            "semilla": semilla,
            "filas_entrenamiento": int(len(X_ent)),
            "filas_validacion": int(len(X_val)),
        },
        "umbral": {
            "valor": umbral,
            "regla": "anómalo si decision_function < umbral",
            "fpr_objetivo_validacion": fpr_objetivo,
            "fpr_real_validacion": fpr_real,
        },
        "filas_negativas_eliminadas_entrenamiento": negativos,
        "semillas": {"division": semilla, "modelo": hiper.get("random_state")},
    }
    joblib.dump(modelo, directorio / "isolation_forest_log1p.joblib")
    with open(directorio / "metadatos_log1p.json", "w", encoding="utf-8") as f:
        json.dump(metadatos, f, ensure_ascii=False, indent=2)
    print(f"  Guardado en: {directorio}")
    return modelo, metadatos


def evaluar_log1p(config: dict, modelo: IsolationForest, umbral: float) -> tuple[dict, pd.DataFrame, int]:
    caracteristicas = config["caracteristicas"]
    etiqueta = config["datos"]["columna_etiqueta"]

    print("\n=== Evaluación (variante log1p, una sola vez) ===")
    df = limpiar(cargar_evaluacion(config), caracteristicas, etiqueta, aplicar_log1p=True)
    negativos = df.attrs.get("filas_negativas_eliminadas", 0)

    puntajes = modelo.decision_function(df[caracteristicas].to_numpy())
    y_pred = (puntajes < umbral).astype(int)
    y_real = (df[etiqueta] != config["datos"]["valor_benigno"]).astype(int).to_numpy()

    metricas = calcular_metricas(y_real, y_pred)
    metricas["umbral"] = umbral
    metricas["roc_auc"] = float(roc_auc_score(y_real, -puntajes))
    metricas["filas_negativas_eliminadas"] = negativos
    por_tipo = metricas_por_tipo(df[etiqueta], y_pred)

    directorio = config["rutas"]["reportes_log1p"]
    directorio.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([metricas]).to_csv(directorio / "metricas.csv", index=False)
    por_tipo.to_csv(directorio / "metricas_por_tipo.csv", index=False)
    guardar_histograma(puntajes, y_real, umbral, directorio / "distribucion_puntajes.png")

    print(f"  Precision: {metricas['precision']:.4f} | Recall: {metricas['recall']:.4f} | "
          f"F1: {metricas['f1']:.4f} | FPR: {metricas['fpr']:.4f} | ROC-AUC: {metricas['roc_auc']:.4f}")
    print(por_tipo.to_string(index=False))
    return metricas, por_tipo, negativos


def ordenar_etiquetas(etiquetas: list[str]) -> list[str]:
    """Primero las etiquetas de interés, en el orden pedido; luego el resto."""
    prioridad = ["BENIGN", "Heartbleed", "Infiltration", "Brute Force", "DoS Hulk", "DDoS", "PortScan"]
    ordenadas = []
    for clave in prioridad:
        ordenadas += [e for e in etiquetas if (e == clave or clave in e) and e not in ordenadas]
    return ordenadas + sorted(e for e in etiquetas if e not in ordenadas)


def escribir_comparacion(config, metricas_log, por_tipo_log, meta_log, negativos_eval) -> Path:
    """Escribe reportes/log1p/comparacion.md con el modelo base y la variante log1p lado a lado."""
    dir_base = config["rutas"]["reportes"]
    base = pd.read_csv(dir_base / config["archivos_salida"]["metricas"]).iloc[0]
    por_tipo_base = pd.read_csv(dir_base / config["archivos_salida"]["metricas_por_tipo"])
    with open(config["rutas"]["modelos"] / config["archivos_salida"]["metadatos"], encoding="utf-8") as f:
        meta_base = json.load(f)

    def fila(nombre, b, l, fmt):
        return f"| {nombre} | {fmt(b)} | {fmt(l)} | {fmt(l - b) if isinstance(b, float) else ''} |"

    pct = lambda v: f"{v:.2%}"  # noqa: E731
    num = lambda v: f"{v:.4f}"  # noqa: E731
    ent = lambda v: f"{int(v):,}"  # noqa: E731

    lineas = [
        "# Comparación: modelo base vs. variante log1p",
        "",
        f"Generado: {datetime.now().isoformat(timespec='seconds')}. Las dos variantes usan la misma",
        "división (semilla 42), los mismos hiperparámetros y la misma regla de umbral (1 % de FPR en",
        "su propia validación). Los archivos de evaluación se usaron una sola vez.",
        "",
        "## Métricas generales",
        "",
        "| Métrica | Base | log1p | Diferencia |",
        "|---|---|---|---|",
        fila("Precision", float(base["precision"]), float(metricas_log["precision"]), num),
        fila("Recall", float(base["recall"]), float(metricas_log["recall"]), num),
        fila("F1", float(base["f1"]), float(metricas_log["f1"]), num),
        fila("FPR (evaluación)", float(base["fpr"]), float(metricas_log["fpr"]), pct),
        fila("ROC-AUC", float(base["roc_auc"]), float(metricas_log["roc_auc"]), num),
        fila("FPR (validación)", float(meta_base["umbral"]["fpr_real_validacion"]),
             float(meta_log["umbral"]["fpr_real_validacion"]), pct),
        f"| Umbral | {base['umbral']:.6f} | {metricas_log['umbral']:.6f} | (escalas distintas, no comparables) |",
        f"| Verdaderos positivos | {ent(base['verdaderos_positivos'])} | {ent(metricas_log['verdaderos_positivos'])} | |",
        f"| Falsos positivos | {ent(base['falsos_positivos'])} | {ent(metricas_log['falsos_positivos'])} | |",
        f"| Flujos evaluados | {ent(base['total_flujos'])} | {ent(metricas_log['total_flujos'])} | |",
        "",
        "## Proporción detectada como anómala por tipo de Label",
        "",
        "En los ataques es el recall; en BENIGN es la tasa de falsos positivos.",
        "",
        "| Label | Flujos base | Base | Flujos log1p | log1p | Diferencia |",
        "|---|---|---|---|---|---|",
    ]
    b = por_tipo_base.set_index("Label")
    l = por_tipo_log.set_index("Label")
    for etiqueta in ordenar_etiquetas(sorted(set(b.index) | set(l.index))):
        fb = b.loc[etiqueta] if etiqueta in b.index else None
        fl = l.loc[etiqueta] if etiqueta in l.index else None
        rb = fb["proporcion_detectada"] if fb is not None else np.nan
        rl = fl["proporcion_detectada"] if fl is not None else np.nan
        dif = f"{(rl - rb) * 100:+.1f} pp" if not (np.isnan(rb) or np.isnan(rl)) else ""
        lineas.append(
            f"| {etiqueta} | {ent(fb['flujos']) if fb is not None else '—'} | {pct(rb) if fb is not None else '—'} "
            f"| {ent(fl['flujos']) if fl is not None else '—'} | {pct(rl) if fl is not None else '—'} | {dif} |"
        )

    negativos_ent = meta_log["filas_negativas_eliminadas_entrenamiento"]
    lineas += [
        "",
        "## Filas perdidas por valores negativos antes de log1p",
        "",
        "Se eliminan después de quitar infinitos, NaN y duplicados, así que solo afectan a la variante log1p.",
        "",
        "| Conjunto | Filas eliminadas |",
        "|---|---|",
        f"| Entrenamiento (lunes, antes de filtrar BENIGN) | {negativos_ent:,} |",
        f"| Evaluación (martes a viernes) | {negativos_eval:,} |",
        "",
        MARCA_FIN_GENERADO,
    ]

    ruta = config["rutas"]["reportes_log1p"] / "comparacion.md"
    # Conserva lo escrito a mano debajo de la marca (por ejemplo, la interpretación).
    manual = ""
    if ruta.exists():
        previo = ruta.read_text(encoding="utf-8")
        if MARCA_FIN_GENERADO in previo:
            manual = previo.split(MARCA_FIN_GENERADO, 1)[1]
    ruta.write_text("\n".join(lineas) + manual, encoding="utf-8")
    return ruta


def main() -> None:
    config = cargar_configuracion()
    modelo, meta = entrenar_log1p(config)
    metricas, por_tipo, negativos_eval = evaluar_log1p(config, modelo, meta["umbral"]["valor"])
    ruta = escribir_comparacion(config, metricas, por_tipo, meta, negativos_eval)
    print(f"\nComparación escrita en: {ruta}")


if __name__ == "__main__":
    main()
