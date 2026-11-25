"""Agrupación de paquetes en flujos y cálculo de las 10 características del modelo.

Este módulo no captura nada ni depende de scapy: recibe paquetes ya resumidos
(``Paquete``) y devuelve flujos cerrados con sus características. Así se puede
probar con pytest sin red.

Se imitan las convenciones de CICFlowMeter (la herramienta que generó CICIDS2017)
para las 10 características que usa el modelo:

* Un flujo es bidireccional: se identifica por (IPs, puertos, protocolo) sin
  importar el sentido. El primer paquete define el sentido "forward" y, por
  tanto, el ``Destination Port``.
* ``Flow Duration`` y ``Flow IAT Mean`` en microsegundos.
* ``Total Length of Fwd/Bwd Packets`` = suma de bytes de carga útil (payload),
  sin cabeceras.
* ``Flow Bytes/s`` y ``Flow Packets/s`` sobre la duración en segundos. Con
  duración 0 (flujo de un solo paquete) quedan infinitos, igual que en el
  dataset; el detector los marca como NO_EVALUABLE.
* ``SYN Flag Count`` = paquetes del flujo con la bandera SYN (ambos sentidos).
* Un flujo TCP termina con RST o cuando ambos extremos enviaron FIN. Cualquier
  flujo termina por inactividad o por superar el tiempo activo máximo.

Es una aproximación: no es CICFlowMeter, así que los valores pueden diferir en
casos borde (retransmisiones, flujos que se cortan a mitad, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field

TCP, UDP, ICMP = 6, 17, 1
NOMBRE_PROTOCOLO = {TCP: "TCP", UDP: "UDP", ICMP: "ICMP"}

# Segundos que se recuerda un flujo TCP cerrado para ignorar sus últimos ACK
# (sin esto, el ACK final tras los FIN crearía un flujo "fantasma" de 1 paquete).
GRACIA_CIERRE_SEGUNDOS = 2.0


@dataclass(frozen=True)
class Paquete:
    """Lo mínimo que hace falta de un paquete para armar flujos."""

    tiempo: float              # segundos (epoch), con decimales
    ip_origen: str
    ip_destino: str
    protocolo: int             # 6 TCP, 17 UDP, 1 ICMP
    puerto_origen: int = 0     # 0 en ICMP
    puerto_destino: int = 0
    carga_util: int = 0        # bytes de payload
    syn: bool = False
    fin: bool = False
    rst: bool = False


@dataclass
class Flujo:
    ip_origen: str
    ip_destino: str
    puerto_origen: int
    puerto_destino: int
    protocolo: int
    inicio: float
    ultimo: float
    paquetes_fwd: int = 0
    paquetes_bwd: int = 0
    bytes_fwd: int = 0
    bytes_bwd: int = 0
    syn: int = 0
    fin_fwd: bool = False
    fin_bwd: bool = False
    rst: bool = False
    motivo_cierre: str = ""
    tiempos: list = field(default_factory=list)

    def es_forward(self, p: Paquete) -> bool:
        return (p.ip_origen, p.puerto_origen) == (self.ip_origen, self.puerto_origen)

    def agregar(self, p: Paquete) -> None:
        if self.es_forward(p):
            self.paquetes_fwd += 1
            self.bytes_fwd += p.carga_util
            self.fin_fwd |= p.fin
        else:
            self.paquetes_bwd += 1
            self.bytes_bwd += p.carga_util
            self.fin_bwd |= p.fin
        self.syn += int(p.syn)
        self.rst |= p.rst
        self.ultimo = max(self.ultimo, p.tiempo)
        self.tiempos.append(p.tiempo)

    @property
    def terminado_por_banderas(self) -> bool:
        return self.protocolo == TCP and (self.rst or (self.fin_fwd and self.fin_bwd))

    @property
    def id_flujo(self) -> str:
        proto = NOMBRE_PROTOCOLO.get(self.protocolo, str(self.protocolo))
        return (f"{proto}-{self.ip_origen}:{self.puerto_origen}-"
                f"{self.ip_destino}:{self.puerto_destino}-{self.inicio:.6f}")

    def caracteristicas(self) -> dict:
        """Las 10 características con los mismos nombres que usa el modelo."""
        duracion_us = (self.ultimo - self.inicio) * 1_000_000
        duracion_s = duracion_us / 1_000_000
        total_paquetes = self.paquetes_fwd + self.paquetes_bwd
        total_bytes = self.bytes_fwd + self.bytes_bwd
        ordenados = sorted(self.tiempos)
        iats = [(b - a) * 1_000_000 for a, b in zip(ordenados, ordenados[1:])]
        return {
            "Flow Duration": duracion_us,
            "Total Fwd Packets": self.paquetes_fwd,
            "Total Backward Packets": self.paquetes_bwd,
            "Total Length of Fwd Packets": self.bytes_fwd,
            "Total Length of Bwd Packets": self.bytes_bwd,
            "Flow Bytes/s": total_bytes / duracion_s if duracion_s > 0 else float("inf"),
            "Flow Packets/s": total_paquetes / duracion_s if duracion_s > 0 else float("inf"),
            "Flow IAT Mean": sum(iats) / len(iats) if iats else 0.0,
            "SYN Flag Count": self.syn,
            "Destination Port": self.puerto_destino,
        }

    def como_fila(self) -> dict:
        """Características + identificación, lista para el detector y los CSV."""
        return {
            "id_flujo": self.id_flujo,
            "ip_origen": self.ip_origen,
            "ip_destino": self.ip_destino,
            "puerto_origen": self.puerto_origen,
            "puerto_destino": self.puerto_destino,
            "protocolo": NOMBRE_PROTOCOLO.get(self.protocolo, str(self.protocolo)),
            "motivo_cierre": self.motivo_cierre,
            **self.caracteristicas(),
        }


def clave_flujo(p: Paquete) -> tuple:
    """Misma clave para los dos sentidos de una conversación."""
    a = (p.ip_origen, p.puerto_origen)
    b = (p.ip_destino, p.puerto_destino)
    return (p.protocolo, *sorted([a, b]))


class TablaFlujos:
    """Mantiene los flujos activos y devuelve los que se van cerrando."""

    def __init__(self, timeout_inactividad: float = 5.0, timeout_activo: float = 120.0):
        if timeout_inactividad <= 0 or timeout_activo <= 0:
            raise ValueError("Los tiempos de espera deben ser mayores que 0.")
        self.timeout_inactividad = timeout_inactividad
        self.timeout_activo = timeout_activo
        self.activos: dict[tuple, Flujo] = {}
        self._cerrados_recientes: dict[tuple, float] = {}
        self.paquetes_procesados = 0

    def agregar_paquete(self, p: Paquete) -> list[Flujo]:
        """Procesa un paquete. Devuelve los flujos que se cerraron por su causa."""
        if p.protocolo not in NOMBRE_PROTOCOLO:
            return []
        self.paquetes_procesados += 1
        clave = clave_flujo(p)
        cerrados: list[Flujo] = []

        # ACK/FIN tardíos de una conexión ya cerrada: se ignoran (salvo un SYN nuevo).
        cierre = self._cerrados_recientes.get(clave)
        if cierre is not None:
            if p.tiempo - cierre <= GRACIA_CIERRE_SEGUNDOS and not p.syn:
                return []
            del self._cerrados_recientes[clave]

        flujo = self.activos.get(clave)
        if flujo is not None and (p.tiempo - flujo.ultimo > self.timeout_inactividad
                                  or p.tiempo - flujo.inicio > self.timeout_activo):
            cerrados.append(self._cerrar(clave, "inactividad" if p.tiempo - flujo.ultimo > self.timeout_inactividad
                                         else "tiempo_activo", p.tiempo))
            flujo = None

        if flujo is None:
            flujo = Flujo(p.ip_origen, p.ip_destino, p.puerto_origen, p.puerto_destino,
                          p.protocolo, inicio=p.tiempo, ultimo=p.tiempo)
            self.activos[clave] = flujo
        flujo.agregar(p)

        if flujo.terminado_por_banderas:
            cerrados.append(self._cerrar(clave, "rst" if flujo.rst else "fin", p.tiempo))
        return cerrados

    def expirar(self, ahora: float) -> list[Flujo]:
        """Cierra los flujos inactivos o demasiado largos. Llamar periódicamente."""
        cerrados = []
        for clave, flujo in list(self.activos.items()):
            if ahora - flujo.ultimo > self.timeout_inactividad:
                cerrados.append(self._cerrar(clave, "inactividad", ahora))
            elif ahora - flujo.inicio > self.timeout_activo:
                cerrados.append(self._cerrar(clave, "tiempo_activo", ahora))
        for clave, cierre in list(self._cerrados_recientes.items()):
            if ahora - cierre > GRACIA_CIERRE_SEGUNDOS:
                del self._cerrados_recientes[clave]
        return cerrados

    def vaciar(self) -> list[Flujo]:
        """Cierra todos los flujos activos (al detener la captura)."""
        return [self._cerrar(clave, "fin_captura", None) for clave in list(self.activos)]

    def _cerrar(self, clave: tuple, motivo: str, ahora: float | None) -> Flujo:
        flujo = self.activos.pop(clave)
        flujo.motivo_cierre = motivo
        if motivo in ("fin", "rst") and ahora is not None:
            self._cerrados_recientes[clave] = ahora
        return flujo
