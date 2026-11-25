"""Compara las métricas antes y después de corregir la deduplicación en la evaluación.

Lee reportes/metricas*_antes_de_auditoria.csv, reportes/metricas*.csv (oficiales,
ya corregidos) y el resumen de la auditoría, y escribe
reportes/comparacion_auditoria_duplicados.md.

Uso (desde PC1/):  python scripts/comparar_auditoria_duplicados.py
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.procesamiento.dataset import cargar_configuracion  # noqa: E402

DESTACADOS = ["PortScan", "DDoS", "DoS Hulk"]


def main() -> None:
    config = cargar_configuracion()
    rep = config["rutas"]["reportes"]
    antes = pd.read_csv(rep / "metricas_antes_de_auditoria.csv").iloc[0]
    despues = pd.read_csv(rep / config["archivos_salida"]["metricas"]).iloc[0]
    tipo_antes = pd.read_csv(rep / "metricas_por_tipo_antes_de_auditoria.csv").set_index("Label")
    tipo_despues = pd.read_csv(rep / config["archivos_salida"]["metricas_por_tipo"]).set_index("Label")
    resumen = pd.read_csv(rep / "auditoria_duplicados_resumen.csv").iloc[0]

    def fila(nombre, clave, fmt):
        a, d = float(antes[clave]), float(despues[clave])
        return f"| {nombre} | {fmt(a)} | {fmt(d)} | {fmt(d - a) if fmt is not ent else f'{d - a:+,.0f}'} |"

    num = lambda v: f"{v:.4f}"  # noqa: E731
    pct = lambda v: f"{v:.2%}"  # noqa: E731
    ent = lambda v: f"{v:,.0f}"  # noqa: E731

    lineas = [
        "# Auditoría de duplicados: métricas antes y después de la corrección",
        "",
        f"Generado: {datetime.now().isoformat(timespec='seconds')}. El modelo y el umbral son los mismos;",
        "solo cambia qué filas de evaluación sobreviven a la deduplicación.",
        "",
        "- **Antes:** duplicados por las 10 características (`keep=\"first\"`). Una fila de ataque",
        "  podía descartarse en favor de una benigna con los mismos valores.",
        "- **Después:** duplicados por las 10 características + `Label`.",
        "",
        "## Diagnóstico",
        "",
        "| Concepto | Valor |",
        "|---|---|",
        f"| Grupos duplicados (mismas 10 características) | {resumen['grupos_duplicados']:,} |",
        f"| Duplicado seguro (una sola etiqueta) | {resumen['grupos_duplicado_seguro']:,} |",
        f"| Duplicado conflictivo (más de una etiqueta) | {resumen['grupos_duplicado_conflictivo']:,} |",
        f"| Filas eliminadas en favor de una fila con otra etiqueta | {resumen['filas_eliminadas_con_etiqueta_distinta_a_la_conservada']:,} |",
        f"| Filas eliminadas con el criterio anterior | {resumen['filas_eliminadas_criterio_actual']:,} |",
        f"| Filas eliminadas con el criterio corregido | {resumen['filas_eliminadas_criterio_corregido']:,} |",
        "",
        "## Métricas generales",
        "",
        "| Métrica | Antes | Después | Diferencia |",
        "|---|---|---|---|",
        fila("Precision", "precision", num),
        fila("Recall", "recall", num),
        fila("F1", "f1", num),
        fila("FPR", "fpr", pct),
        fila("ROC-AUC", "roc_auc", num),
        fila("Verdaderos positivos", "verdaderos_positivos", ent),
        fila("Falsos positivos", "falsos_positivos", ent),
        fila("Falsos negativos", "falsos_negativos", ent),
        fila("Flujos evaluados", "total_flujos", ent),
        "",
        "## Proporción detectada por tipo de Label",
        "",
        "En los ataques es el recall; en BENIGN es la tasa de falsos positivos. "
        "Los ataques de volumen van en **negrita**.",
        "",
        "| Label | Flujos antes | Detección antes | Flujos después | Detección después | Diferencia |",
        "|---|---|---|---|---|---|",
    ]
    etiquetas = list(tipo_despues.sort_values("flujos", ascending=False).index)
    etiquetas += [e for e in tipo_antes.index if e not in etiquetas]
    orden = [e for e in DESTACADOS if e in etiquetas] + [e for e in etiquetas if e not in DESTACADOS]
    for e in orden:
        a = tipo_antes.loc[e] if e in tipo_antes.index else None
        d = tipo_despues.loc[e] if e in tipo_despues.index else None
        nombre = f"**{e}**" if e in DESTACADOS else e
        ra = a["proporcion_detectada"] if a is not None else float("nan")
        rd = d["proporcion_detectada"] if d is not None else float("nan")
        lineas.append(
            f"| {nombre} | {ent(a['flujos']) if a is not None else '—'} | {pct(ra) if a is not None else '—'} "
            f"| {ent(d['flujos']) if d is not None else '—'} | {pct(rd) if d is not None else '—'} "
            f"| {(rd - ra) * 100:+.2f} pp |"
        )

    # Conclusión basada en los datos, sin suavizar en ningún sentido.
    volumen = {e: float(tipo_despues.loc[e, "proporcion_detectada"])
               for e in DESTACADOS if e in tipo_despues.index}
    recuperadas = {e: int(tipo_despues.loc[e, "flujos"] - tipo_antes.loc[e, "flujos"])
                   for e in DESTACADOS if e in tipo_despues.index and e in tipo_antes.index}
    lineas += ["", "## Conclusión", ""]
    if all(v == 0 for v in volumen.values()):
        lineas.append(
            "El recall de los ataques de volumen (" + ", ".join(volumen) + ") **sigue en 0 % después de "
            "la corrección**. El problema de deduplicación era real ("
            f"{resumen['grupos_duplicado_conflictivo']:,} grupos conflictivos), pero solo devolvió a la "
            "evaluación " + ", ".join(f"{n:+,} filas de {e}" for e, n in recuperadas.items()) + ". Casi "
            "todas esas filas tienen exactamente las mismas 10 características que alguna fila BENIGN, y "
            "el modelo solo ve esas características: les da el mismo puntaje que al tráfico normal. "
            "**El bug no explicaba el 0 %:** la limitación estructural de "
            "Isolation Forest con los ataques de volumen sigue siendo válida."
        )
    else:
        lineas.append(
            "**El recall de los ataques de volumen cambió con la corrección:** "
            + ", ".join(f"{e} = {v:.2%}" for e, v in volumen.items())
            + ". El bug de deduplicación sí afectaba ese resultado."
        )
    lineas.append(
        f"\nEn términos globales, los verdaderos positivos pasan de {int(antes['verdaderos_positivos']):,} "
        f"a {int(despues['verdaderos_positivos']):,} y el ROC-AUC de {antes['roc_auc']:.4f} a "
        f"{despues['roc_auc']:.4f}."
    )

    ruta = rep / "comparacion_auditoria_duplicados.md"
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    print(f"Comparación escrita en: {ruta}")


if __name__ == "__main__":
    main()
