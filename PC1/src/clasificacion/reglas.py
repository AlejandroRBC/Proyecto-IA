"""Reglas por ventana de tiempo e IP de origen que detectan y nombran ataques.

Isolation Forest mira cada flujo por separado: una conexión de una ráfaga o un sondeo
de un escaneo, vistos solos, son normales. Lo anómalo es **cuántos** llegan desde la
misma IP en pocos segundos. Estas reglas guardan, por cada IP atacante, los flujos de
los últimos ``ventana_segundos`` y cuentan:

* ``escaneo_puertos``: puertos de destino distintos  >= ``min_puertos_escaneo``.
* ``rafaga_conexiones``: conexiones TCP cortas (< ``bytes_transferencia_masiva``) al
  mismo puerto  >= ``min_conexiones_rafaga``.
* ``transferencia_masiva``: el flujo trae >= ``bytes_transferencia_masiva`` del servidor
  y el modelo lo marcó ANOMALO, o la ventana ya suma >= ``bytes_ventana_masiva``.
* ``anomalia_sin_clasificar``: ANOMALO para el modelo sin ninguna regla que lo explique.

Cada (IP atacante, tipo) forma un **incidente**: mientras siga llegando tráfico que
cumple la regla se actualiza (no se abre otro); tras ``inactividad_incidente_segundos``
sin actividad, el siguiente abre uno nuevo. Así una ráfaga de miles de conexiones es
un incidente, no miles de alertas.

Funciona igual en vivo (lotes del capturador) y sobre un CSV ya guardado.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime

import pandas as pd

ESCANEO = "escaneo_puertos"
RAFAGA = "rafaga_conexiones"
TRANSFERENCIA = "transferencia_masiva"
SIN_CLASIFICAR = "anomalia_sin_clasificar"
TIPOS_ATAQUE = [ESCANEO, RAFAGA, TRANSFERENCIA, SIN_CLASIFICAR]

NOMBRES = {ESCANEO: "Escaneo de puertos", RAFAGA: "Ráfaga de conexiones (DoS)",
           TRANSFERENCIA: "Transferencia masiva", SIN_CLASIFICAR: "Anomalía sin clasificar"}

PARAMETROS_POR_DEFECTO = {
    "ventana_segundos": 10,
    "min_puertos_escaneo": 15,
    "min_conexiones_rafaga": 50,
    "bytes_transferencia_masiva": 20_000,
    "bytes_ventana_masiva": 5_000_000,
    "inactividad_incidente_segundos": 30,
}

# Un flujo está "al revés" si el puerto de origen parece de servicio (< 10000) y el de
# destino de cliente (>= 10000). No se usa el rango efímero de Windows (49152+) porque
# en el laboratorio PC2 abrió conexiones desde puertos 13000-19000.
PUERTO_CLIENTE_MIN = 10_000

COLUMNAS_INCIDENTE = [
    "fecha_hora", "id_incidente", "tipo_ataque", "ip_atacante", "ip_victima", "inicio", "ultimo",
    "duracion_segundos", "flujos", "flujos_anomalos_modelo", "puertos_distintos",
    "conexiones_por_segundo", "bytes_servidor", "detectado_por", "detalle",
]


def _numero(valor, por_defecto: float = 0.0) -> float:
    try:
        v = float(valor)
    except (TypeError, ValueError):
        return por_defecto
    return por_defecto if v != v else v  # NaN


def _tiempo(valor) -> datetime:
    if isinstance(valor, datetime):
        return valor
    return pd.Timestamp(valor).to_pydatetime()


@dataclass
class Orientado:
    atacante: str
    victima: str
    puerto: int          # puerto del servicio atacado (0 en ICMP)
    tcp: bool
    bytes_servidor: float
    al_reves: bool


def orientar(fila: dict) -> Orientado:
    """Quién inicia la conversación, a qué servicio y cuántos bytes envió el servidor.

    Si la captura perdió el primer paquete del cliente (el SYN), el flujo empieza con
    un paquete del servidor y queda "al revés": puerto de servicio como origen y un
    puerto efímero como destino. Se detecta por los puertos y se da la vuelta.
    """
    protocolo = str(fila.get("protocolo", ""))
    origen, destino = str(fila.get("ip_origen", "")), str(fila.get("ip_destino", ""))
    p_origen = int(_numero(fila.get("puerto_origen")))
    p_destino = int(_numero(fila.get("puerto_destino", fila.get("Destination Port"))))
    fwd = _numero(fila.get("Total Length of Fwd Packets"))
    bwd = _numero(fila.get("Total Length of Bwd Packets"))
    al_reves = protocolo in ("TCP", "UDP") and p_destino >= PUERTO_CLIENTE_MIN > p_origen
    if al_reves:
        return Orientado(destino, origen, p_origen, protocolo == "TCP", fwd, True)
    return Orientado(origen, destino, p_destino, protocolo == "TCP", bwd, False)


@dataclass
class _Registro:
    t: datetime
    puerto: int
    tcp: bool
    bytes_servidor: float
    corta: bool


@dataclass
class Incidente:
    id_incidente: str
    tipo_ataque: str
    ip_atacante: str
    inicio: datetime
    ultimo: datetime
    victimas: set = field(default_factory=set)
    puertos: set = field(default_factory=set)
    flujos: int = 0
    flujos_anomalos_modelo: int = 0
    bytes_servidor: float = 0.0
    max_conexiones_por_segundo: float = 0.0

    def como_fila(self) -> dict:
        duracion = (self.ultimo - self.inicio).total_seconds()
        modelo = self.flujos_anomalos_modelo > 0
        reglas = self.tipo_ataque in (ESCANEO, RAFAGA, TRANSFERENCIA)
        return {
            "fecha_hora": datetime.now().isoformat(timespec="milliseconds"),
            "id_incidente": self.id_incidente,
            "tipo_ataque": self.tipo_ataque,
            "ip_atacante": self.ip_atacante,
            "ip_victima": ", ".join(sorted(self.victimas)[:3]) + (" ..." if len(self.victimas) > 3 else ""),
            "inicio": self.inicio.isoformat(timespec="milliseconds"),
            "ultimo": self.ultimo.isoformat(timespec="milliseconds"),
            "duracion_segundos": round(duracion, 1),
            "flujos": self.flujos,
            "flujos_anomalos_modelo": self.flujos_anomalos_modelo,
            "puertos_distintos": len(self.puertos),
            "conexiones_por_segundo": round(self.max_conexiones_por_segundo, 1),
            "bytes_servidor": int(self.bytes_servidor),
            "detectado_por": ("modelo + reglas" if modelo and reglas else "reglas" if reglas
                              else "modelo + random forest" if self.tipo_ataque.startswith("rf:") else "modelo"),
            "detalle": self.detalle(),
        }

    def detalle(self) -> str:
        if self.tipo_ataque == ESCANEO:
            return f"{len(self.puertos)} puertos distintos sondeados"
        if self.tipo_ataque == RAFAGA:
            puertos = ", ".join(str(p) for p in sorted(self.puertos)[:3])
            return f"hasta {self.max_conexiones_por_segundo:.0f} conexiones/s al puerto {puertos}"
        if self.tipo_ataque == TRANSFERENCIA:
            return f"{self.bytes_servidor / 1_000_000:.1f} MB transferidos en {self.flujos} flujos"
        if self.tipo_ataque.startswith("rf:"):
            return f"{self.flujos} flujos anómalos; familia según el Random Forest (CICIDS2017)"
        return f"{self.flujos} flujos anómalos sin patrón de ventana"


class ClasificadorVentana:
    """Estado de las ventanas por IP y de los incidentes abiertos."""

    def __init__(self, parametros: dict | None = None):
        self.p = {**PARAMETROS_POR_DEFECTO, **(parametros or {})}
        self.ventanas: dict[str, deque[_Registro]] = defaultdict(deque)
        self.incidentes: dict[tuple[str, str], Incidente] = {}
        self.todos: list[Incidente] = []

    # ------------------------------------------------------------------
    def _tipo(self, fila: dict, o: Orientado, ventana: deque[_Registro]) -> str | None:
        p = self.p
        anomalo = str(fila.get("resultado")) == "ANOMALO"
        grande = o.bytes_servidor >= p["bytes_transferencia_masiva"]
        puertos = {r.puerto for r in ventana if r.puerto > 0}
        if len(puertos) >= p["min_puertos_escaneo"]:
            return ESCANEO
        if grande and anomalo:
            return TRANSFERENCIA
        if o.tcp and not grande:
            mismas = sum(1 for r in ventana if r.tcp and r.corta and r.puerto == o.puerto)
            if mismas >= p["min_conexiones_rafaga"]:
                return RAFAGA
        if grande and sum(r.bytes_servidor for r in ventana) >= p["bytes_ventana_masiva"]:
            return TRANSFERENCIA
        if anomalo:
            # Sin regla que lo explique: familia del Random Forest si la hay (ver clasificador.py).
            familia_rf = str(fila.get("familia_rf") or "")
            prob = _numero(fila.get("prob_rf"))
            if familia_rf and familia_rf != "BENIGN" and prob >= p.get("probabilidad_minima_rf", 0.5):
                return f"rf:{familia_rf}"
            return SIN_CLASIFICAR
        return None

    def _incidente(self, tipo: str, o: Orientado, t: datetime) -> tuple[Incidente, bool]:
        clave = (o.atacante, tipo)
        actual = self.incidentes.get(clave)
        if actual is not None and (t - actual.ultimo).total_seconds() <= self.p["inactividad_incidente_segundos"]:
            return actual, False
        nuevo = Incidente(f"{tipo}-{o.atacante}-{t:%Y%m%d-%H%M%S}", tipo, o.atacante, t, t)
        self.incidentes[clave] = nuevo
        self.todos.append(nuevo)
        return nuevo, True

    def procesar(self, filas: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
        """Clasifica ``filas`` (en orden de inicio) y actualiza los incidentes.

        Añade a cada fila ``tipo_ataque`` e ``id_incidente`` ('' si es normal).
        Devuelve ``(filas, incidentes_tocados, incidentes_nuevos)``; los incidentes,
        como filas listas para el CSV.
        """
        tocados: dict[str, Incidente] = {}
        nuevos: list[Incidente] = []
        orden = sorted(range(len(filas)), key=lambda i: _tiempo(filas[i]["inicio_flujo"]))
        for i in orden:
            fila = filas[i]
            t = _tiempo(fila["inicio_flujo"])
            o = orientar(fila)
            ventana = self.ventanas[o.atacante]
            ventana.append(_Registro(t, o.puerto, o.tcp, o.bytes_servidor,
                                     o.bytes_servidor < self.p["bytes_transferencia_masiva"]))
            while ventana and (t - ventana[0].t).total_seconds() > self.p["ventana_segundos"]:
                ventana.popleft()
            tipo = self._tipo(fila, o, ventana)
            fila["tipo_ataque"] = tipo or ""
            fila["id_incidente"] = ""
            if tipo is None:
                continue
            inc, es_nuevo = self._incidente(tipo, o, t)
            inc.ultimo = max(inc.ultimo, t)
            inc.victimas.add(o.victima)
            if o.puerto > 0:
                inc.puertos.add(o.puerto)
            inc.flujos += 1
            inc.flujos_anomalos_modelo += int(str(fila.get("resultado")) == "ANOMALO")
            inc.bytes_servidor += o.bytes_servidor
            if tipo == RAFAGA:
                mismas = sum(1 for r in ventana if r.tcp and r.corta and r.puerto == o.puerto)
                inc.max_conexiones_por_segundo = max(inc.max_conexiones_por_segundo,
                                                     mismas / self.p["ventana_segundos"])
            fila["id_incidente"] = inc.id_incidente
            tocados[inc.id_incidente] = inc
            if es_nuevo:
                nuevos.append(inc)
        return filas, [inc.como_fila() for inc in tocados.values()], [inc.como_fila() for inc in nuevos]

    def resumen(self) -> pd.DataFrame:
        """Estado final de todos los incidentes (una fila por incidente)."""
        return pd.DataFrame([inc.como_fila() for inc in self.todos], columns=COLUMNAS_INCIDENTE)


def clasificar_dataframe(df: pd.DataFrame, parametros: dict | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Aplica las reglas a una sesión guardada. Devuelve (flujos con tipo_ataque, incidentes)."""
    clasificador = ClasificadorVentana(parametros)
    filas = df.to_dict("records")
    for fila in filas:
        if "inicio_flujo" not in fila or pd.isna(fila["inicio_flujo"]):
            fila["inicio_flujo"] = fila.get("inicio")
    clasificador.procesar(filas)
    salida = df.copy()
    salida["tipo_ataque"] = [f["tipo_ataque"] for f in filas]
    salida["id_incidente"] = [f["id_incidente"] for f in filas]
    return salida, clasificador.resumen()


def nombre_tipo(tipo: str) -> str:
    """Nombre legible de un tipo de ataque (incluidos los ``rf:<familia>``)."""
    if str(tipo).startswith("rf:"):
        return f"{tipo[3:]} (Random Forest)"
    return NOMBRES.get(tipo, tipo)


def describir_incidente(fila: dict) -> str:
    """Línea de consola para un incidente nuevo."""
    return (f"[INCIDENTE] {nombre_tipo(fila['tipo_ataque']).upper()}  "
            f"{fila['ip_atacante']} -> {fila['ip_victima']}  ({fila['detalle']}; "
            f"detectado por {fila['detectado_por']})")
