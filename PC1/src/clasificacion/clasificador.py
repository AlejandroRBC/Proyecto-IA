"""Clasificador de ataques completo: reglas por ventana + Random Forest opcional.

Orden de decisión para cada flujo (ver ``reglas.ClasificadorVentana._tipo``):
  1. Reglas por ventana (escaneo, ráfaga, transferencia masiva): medidas en el laboratorio.
  2. Si el flujo es ANOMALO y ninguna regla lo explica, la familia del Random Forest
     (``rf:<familia>``) si es un ataque con probabilidad suficiente.
  3. Si no, ``anomalia_sin_clasificar``.
"""

from __future__ import annotations

from src.clasificacion.modelo_ataques import BENIGN, cargar_clasificador, predecir_familias
from src.clasificacion.reglas import PARAMETROS_POR_DEFECTO, ClasificadorVentana


class ClasificadorAtaques:
    def __init__(self, config: dict | None = None, clasificador_rf: dict | None = None, usar_rf: bool | None = None):
        ajustes = dict((config or {}).get("clasificacion") or {})
        parametros = {k: ajustes[k] for k in PARAMETROS_POR_DEFECTO if k in ajustes}
        parametros["probabilidad_minima_rf"] = float(ajustes.get("probabilidad_minima_rf", 0.5))
        self.ventana = ClasificadorVentana(parametros)
        usar_rf = bool(ajustes.get("usar_random_forest", True)) if usar_rf is None else usar_rf
        if clasificador_rf is None and usar_rf and config is not None:
            clasificador_rf = cargar_clasificador(config)
        self.rf = clasificador_rf if usar_rf else None

    @property
    def total_incidentes(self) -> int:
        return len(self.ventana.todos)

    def conteo_por_tipo(self) -> dict:
        conteo: dict[str, int] = {}
        for inc in self.ventana.todos:
            conteo[inc.tipo_ataque] = conteo.get(inc.tipo_ataque, 0) + 1
        return conteo

    def procesar(self, filas: list[dict]) -> tuple[list[dict], list[dict]]:
        """Añade ``tipo_ataque``, ``id_incidente``, ``familia_rf`` y ``prob_rf`` a las filas.

        Devuelve ``(incidentes_tocados, incidentes_nuevos)`` como filas para el CSV.
        """
        for fila in filas:
            fila.setdefault("familia_rf", "")
            fila.setdefault("prob_rf", None)
        if self.rf is not None:
            anomalas = [f for f in filas if str(f.get("resultado")) == "ANOMALO"]
            for fila, pred in zip(anomalas, predecir_familias(self.rf, anomalas)):
                if pred is not None:
                    fila["familia_rf"], fila["prob_rf"] = pred[0], round(pred[1], 3)
        _, tocados, nuevos = self.ventana.procesar(filas)
        return tocados, nuevos


__all__ = ["ClasificadorAtaques", "BENIGN"]
