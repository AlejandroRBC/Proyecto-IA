"""Escenario aleatorio: tráfico normal continuo con episodios anómalos en momentos al azar.

A diferencia del escenario mixto (tres fases fijas), aquí:

* El tráfico normal (ping + descarga pequeña con pausas al azar) corre **todo el
  tiempo**, también durante los episodios anómalos, como en una red real donde el
  ataque se suma al uso normal.
* Los episodios anómalos empiezan en momentos al azar, duran un tiempo al azar y son
  de un tipo al azar:
    - ``descargas``: 1-3 descargas en paralelo y seguidas de grande.bin (~256 KB);
    - ``descargas_y_rafaga``: lo anterior + ráfaga de conexiones;
    - ``rafaga``: solo ráfaga (el modelo casi nunca la marca: sirve para mostrarlo).
* La planificación sale de una semilla que se imprime y se registra, así una
  ejecución se puede repetir exactamente.

En el CSV de escenarios cada tramo es una fila: ``mixto_normal`` para los tramos sin
episodio y ``mixto_anomalo`` para cada episodio (con su tipo e intensidad), así PC1
puede cruzar los flujos con los episodios. Ojo: el tráfico normal que ocurre durante
un episodio cae dentro de su intervalo.
"""

import random
import threading
import time

from .configuracion import (
    ErrorConfiguracion,
    ruta_registro,
    validar_ip_destino,
    validar_parametros_aleatorio,
    validar_parametros_rafaga,
)
from .escenario_mixto import (
    TIPO_ANOMALO,
    TIPO_NORMAL,
    Contador,
    _trabajador_descargas,
    _trabajador_normal,
    _trabajador_rafagas,
    acciones_reales,
)
from .registrador import ahora, ip_local_hacia, registrar_escenario


def planificar_aleatorio(config: dict, total=None, semilla=None) -> dict:
    """Plan de episodios anómalos (función pura): {"semilla", "total", "episodios": [...]}.

    Cada episodio: {"inicio": s desde el comienzo, "duracion": s, "tipo", "descargas_paralelas"}.
    Se garantiza un margen normal al inicio y al final, y al menos un episodio si cabe.
    """
    p = validar_parametros_aleatorio(config)
    total = float(p["duracion_total_segundos"] if total is None else total)
    if total <= 0:
        raise ErrorConfiguracion("La duración del escenario aleatorio debe ser mayor que 0.")
    total = min(total, p["duracion_total_maxima_segundos"])
    if semilla is None:
        semilla = p["semilla"] if p["semilla"] is not None else random.SystemRandom().randrange(1, 1_000_000)
    azar = random.Random(semilla)
    margen = min(p["normal_al_inicio_y_final_segundos"], total / 4)
    pausa_min, pausa_max = p["pausa_entre_episodios_segundos"]
    dur_min, dur_max = p["duracion_episodio_segundos"]
    tipos, pesos = zip(*p["pesos_tipo_episodio"].items())
    descargas_min, descargas_max = p["descargas_paralelas_rango"]

    def nuevo(inicio, duracion):
        tipo = azar.choices(tipos, weights=pesos)[0]
        return {"inicio": round(inicio, 2), "duracion": round(duracion, 2), "tipo": tipo,
                "descargas_paralelas": 0 if tipo == "rafaga" else azar.randint(descargas_min, descargas_max)}

    episodios = []
    t = margen + azar.uniform(0, pausa_max / 2)
    while True:
        duracion = azar.uniform(dur_min, dur_max)
        if t + duracion > total - margen:
            break
        episodios.append(nuevo(t, duracion))
        t += duracion + azar.uniform(pausa_min, pausa_max)
    if not episodios:
        # Duración corta: un único episodio centrado, tan largo como quepa.
        duracion = min(dur_max, max(total - 2 * margen, 0))
        if duracion >= min(dur_min, 1):
            episodios.append(nuevo((total - duracion) / 2, duracion))
    return {"semilla": semilla, "total": total, "episodios": episodios}


def describir_plan(plan: dict) -> str:
    lineas = [f"  Plan aleatorio (semilla {plan['semilla']}, {plan['total']:.0f} s, "
              f"{len(plan['episodios'])} episodios anómalos):"]
    for i, ep in enumerate(plan["episodios"], 1):
        minuto = f"{int(ep['inicio'] // 60):02d}:{int(ep['inicio'] % 60):02d}"
        extra = f", {ep['descargas_paralelas']} descargas en paralelo" if ep["descargas_paralelas"] else ""
        lineas.append(f"    {i}. a los {minuto} durante {ep['duracion']:.0f} s: {ep['tipo']}{extra}")
    return "\n".join(lineas)


def _dormir_hasta(objetivo, etiqueta, intervalo_progreso, contadores):
    """Espera en el hilo principal (Ctrl+C se atiende al momento) e imprime el progreso."""
    siguiente = time.monotonic() + intervalo_progreso
    while time.monotonic() < objetivo:
        time.sleep(min(0.25, max(objetivo - time.monotonic(), 0)))
        if time.monotonic() >= siguiente:
            detalle = " | ".join(", ".join(f"{k}={v}" for k, v in sorted(c.valores().items())) or "-"
                                 for c in contadores)
            print(f"  [{etiqueta}] quedan {max(objetivo - time.monotonic(), 0):4.0f} s | {detalle}")
            siguiente += intervalo_progreso


def _diferencia(antes: dict, despues: dict) -> dict:
    return {k: v - antes.get(k, 0) for k, v in despues.items() if v - antes.get(k, 0)}


def ejecutar_escenario_aleatorio(config: dict, total=None, semilla=None, acciones=None, registrar=True,
                                 intervalo_progreso: float = 5.0, mostrar_plan: bool = True) -> list:
    """Ejecuta el plan aleatorio y devuelve las filas registradas (una por tramo)."""
    ip = validar_ip_destino(config)
    p = validar_parametros_aleatorio(config)
    plan = planificar_aleatorio(config, total, semilla)
    if any(ep["tipo"] != "descargas" for ep in plan["episodios"]):
        validar_parametros_rafaga(config)
    acciones = acciones or acciones_reales(config)
    ip_origen = ip_local_hacia(ip)
    if mostrar_plan:
        print(describir_plan(plan))

    filas = []

    def anotar(tipo, inicio, parametros):
        fila = {"fecha_hora_inicio": inicio, "fecha_hora_fin": ahora(), "tipo_escenario": tipo,
                "parametros": {"semilla": plan["semilla"], **parametros}, "ip_destino": ip,
                "ip_origen": ip_origen}
        if registrar:
            registrar_escenario(ruta_registro(config), fila)
        filas.append(fila)
        return fila

    comienzo = time.monotonic()
    fin_total = comienzo + plan["total"]
    parar_todo = threading.Event()
    normal = Contador()
    hilo_normal = threading.Thread(target=_trabajador_normal, args=(acciones, p, fin_total, parar_todo, normal),
                                   daemon=True)
    hilo_normal.start()

    tramo, inicio_tramo, antes = "normal", ahora(), normal.valores()
    try:
        for n, ep in enumerate(plan["episodios"], 1):
            _dormir_hasta(comienzo + ep["inicio"], "normal", intervalo_progreso, [normal])
            anotar(TIPO_NORMAL, inicio_tramo, {"tramo": "normal", **_diferencia(antes, normal.valores())})

            print(f"\n  >>> Episodio ANÓMALO {n}/{len(plan['episodios'])}: {ep['tipo']} durante {ep['duracion']:.0f} s")
            tramo, inicio_tramo, antes = f"episodio {n}", ahora(), normal.valores()
            fin_ep = comienzo + ep["inicio"] + ep["duracion"]
            parar_ep = threading.Event()
            anomalo = Contador()
            hilos = [threading.Thread(target=_trabajador_descargas, args=(acciones, p, fin_ep, parar_ep, anomalo),
                                      daemon=True) for _ in range(ep["descargas_paralelas"])]
            if ep["tipo"] != "descargas":
                hilos.append(threading.Thread(target=_trabajador_rafagas, args=(acciones, fin_ep, parar_ep, anomalo),
                                              daemon=True))
            for h in hilos:
                h.start()
            try:
                _dormir_hasta(fin_ep, f"episodio {n}: {ep['tipo']}", intervalo_progreso, [anomalo])
            finally:
                parar_ep.set()
                for h in hilos:
                    h.join(timeout=10)
            anotar(TIPO_ANOMALO, inicio_tramo, {"tramo": f"episodio {n}", "tipo_episodio": ep["tipo"],
                                                "descargas_paralelas": ep["descargas_paralelas"],
                                                "duracion_planificada_segundos": ep["duracion"],
                                                **anomalo.valores(), "trafico_normal_simultaneo":
                                                _diferencia(antes, normal.valores())})
            if anomalo.primer_error:
                print(f"  Aviso: errores en el episodio {n} (primero: {anomalo.primer_error}).")
            tramo, inicio_tramo, antes = "normal", ahora(), normal.valores()
        _dormir_hasta(fin_total, "normal", intervalo_progreso, [normal])
        anotar(TIPO_NORMAL, inicio_tramo, {"tramo": "normal", **_diferencia(antes, normal.valores())})
    except KeyboardInterrupt:
        print(f"\n  Escenario aleatorio interrumpido durante el tramo '{tramo}'.")
        tipo = TIPO_NORMAL if tramo == "normal" else TIPO_ANOMALO
        anotar(tipo, inicio_tramo, {"tramo": tramo, "interrumpida": True,
                                    **_diferencia(antes, normal.valores())})
    finally:
        parar_todo.set()
        hilo_normal.join(timeout=10)
    if normal.primer_error:
        print(f"  Aviso: errores en el tráfico normal (primero: {normal.primer_error}).")
    return filas
