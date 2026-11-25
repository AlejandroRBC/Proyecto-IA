"""Menú de consola de PC2: genera tráfico de laboratorio hacia PC1.

Uso:  python menu.py                      (usa configuracion.yaml de esta carpeta)
      python menu.py --config otra.yaml
"""

import argparse
import sys
from pathlib import Path

CARPETA = Path(__file__).resolve().parent
sys.path.insert(0, str(CARPETA / "src"))

from generador_trafico.configuracion import (  # noqa: E402
    ErrorConfiguracion,
    cargar_configuracion,
    planificar_fases,
    ruta_registro,
    validar_ip_destino,
    validar_parametros_aleatorio,
    validar_parametros_mixto,
    validar_parametros_rafaga,
)
from generador_trafico.escenario_aleatorio import (  # noqa: E402
    describir_plan,
    ejecutar_escenario_aleatorio,
    planificar_aleatorio,
)
from generador_trafico.escenario_mixto import ejecutar_escenario_mixto, verificar_servidor  # noqa: E402
from generador_trafico.escaneo_puertos import escanear_puertos  # noqa: E402
from generador_trafico.rafagas import generar_rafaga  # noqa: E402
from generador_trafico.registrador import (  # noqa: E402
    ahora,
    ip_local_hacia,
    leer_ultimos_escenarios,
    registrar_escenario,
)
from generador_trafico.trafico_normal import construir_url_http, descargar_archivo_http, enviar_ping  # noqa: E402

OPCIONES = """
========== PC2 - Generador de tráfico de laboratorio ==========
  1. Generar tráfico normal (ping)
  2. Escanear puertos de PC1
  3. Generar ráfaga de conexiones
  4. Escenario mixto para la demo (normal -> anómalo -> normal)
  5. Escenario aleatorio (normal continuo + episodios anómalos al azar)
  6. Ver últimos escenarios registrados
  7. Salir
==============================================================="""


def preguntar_si_no(mensaje: str) -> bool:
    return input(f"{mensaje} (s/n): ").strip().lower() in ("s", "si", "sí")


def confirmar_ataque(ip: str, descripcion: str) -> bool:
    print(f"\n  ATENCIÓN: se va a ejecutar '{descripcion}'.")
    print(f"  IP destino configurada (PC1): {ip}")
    return preguntar_si_no("  ¿Confirmas que esta es la IP de PC1 en la red de laboratorio?")


def ejecutar_y_registrar(config: dict, tipo: str, funcion) -> None:
    """Corre un escenario y lo anota en el CSV solo si terminó bien."""
    ip = validar_ip_destino(config)
    inicio = ahora()
    parametros = funcion()
    fin = ahora()
    registrar_escenario(ruta_registro(config), {
        "fecha_hora_inicio": inicio,
        "fecha_hora_fin": fin,
        "tipo_escenario": tipo,
        "parametros": parametros,
        "ip_destino": ip,
        "ip_origen": ip_local_hacia(ip),
    })
    print(f"  Escenario '{tipo}' registrado ({inicio} -> {fin}).")


def opcion_trafico_normal(config: dict) -> None:
    ejecutar_y_registrar(config, "trafico_normal_ping", lambda: enviar_ping(config))
    if preguntar_si_no("\n  ¿PC1 tiene un servidor HTTP corriendo (python -m http.server) y quieres descargar?"):
        url = construir_url_http(config)
        ejecutar_y_registrar(config, "trafico_normal_http", lambda: descargar_archivo_http(config, url))


def opcion_escaneo(config: dict) -> None:
    ip = validar_ip_destino(config)
    if not confirmar_ataque(ip, "escaneo de puertos con nmap"):
        print("  Cancelado.")
        return

    def correr():
        resultado = escanear_puertos(config)
        return {"comando": resultado["comando"], "puertos_abiertos": len(resultado["puertos_abiertos"])}

    ejecutar_y_registrar(config, "escaneo_puertos", correr)


def opcion_rafaga(config: dict) -> None:
    ip = validar_ip_destino(config)
    parametros = validar_parametros_rafaga(config)
    maximo = parametros["duracion_maxima_segundos"]
    texto = input(f"  Duración en segundos (Enter = {maximo}, máximo {maximo}): ").strip()
    duracion = None
    if texto:
        try:
            duracion = float(texto)
        except ValueError:
            print("  Valor no numérico; se usará el máximo configurado.")
        else:
            if duracion > maximo:
                print(f"  Se pidió {duracion:g} s, pero el máximo es {maximo} s: se recorta a {maximo} s.")
    descripcion = (f"ráfaga TCP a puerto {parametros['puerto_destino']}, "
                   f"{parametros['conexiones_por_segundo']} conexiones/s")
    if not confirmar_ataque(ip, descripcion):
        print("  Cancelado.")
        return
    print("  (Ctrl+C para detenerla antes)")
    ejecutar_y_registrar(config, "rafaga_conexiones", lambda: generar_rafaga(config, duracion))


def opcion_mixto(config: dict) -> None:
    ip = validar_ip_destino(config)
    parametros = validar_parametros_mixto(config)
    defecto, maximo = parametros["duracion_total_segundos"], parametros["duracion_total_maxima_segundos"]
    texto = input(f"  Duración total en segundos (Enter = {defecto:g}, máximo {maximo:g}): ").strip()
    total = None
    if texto:
        try:
            total = float(texto)
        except ValueError:
            print(f"  Valor no numérico; se usarán {defecto:g} s.")
        else:
            if total > maximo:
                print(f"  Se pidió {total:g} s, pero el máximo es {maximo:g} s: se recorta.")
    fases = planificar_fases(config, total)
    print("  Plan: " + " -> ".join(f"{nombre} {segundos:.0f} s" for nombre, segundos in fases))
    print(f"  Fase anómala: {parametros['descargas_paralelas']} descargas en paralelo de "
          f"{parametros['archivo_grande']}" + (" + ráfagas de conexiones" if parametros["incluir_rafaga"] else ""))
    print("  Requiere en PC1: python scripts/servidor_demo.py (sirve los archivos en los puertos 8000 y 8080).")
    tamanos = verificar_servidor(config)   # falla con un mensaje claro si PC1 no sirve los archivos
    print(f"  Servidor de PC1 correcto: {parametros['archivo_normal']} = {tamanos['archivo_normal']} B, "
          f"{parametros['archivo_grande']} = {tamanos['archivo_grande']:,} B.")
    if not confirmar_ataque(ip, "escenario mixto con fase anómala"):
        print("  Cancelado.")
        return
    print("  (Ctrl+C para detenerlo; las fases ya hechas quedan registradas)")
    filas = ejecutar_escenario_mixto(config, total)
    print(f"\n  Escenario mixto terminado: {len(filas)} fases registradas en {ruta_registro(config)}.")


def leer_numero(mensaje: str, defecto=None):
    texto = input(mensaje).strip()
    if not texto:
        return defecto
    try:
        return float(texto)
    except ValueError:
        print("  Valor no numérico; se usa el valor por defecto.")
        return defecto


def opcion_aleatorio(config: dict) -> None:
    ip = validar_ip_destino(config)
    parametros = validar_parametros_aleatorio(config)
    defecto, maximo = parametros["duracion_total_segundos"], parametros["duracion_total_maxima_segundos"]
    total = leer_numero(f"  Duración total en segundos (Enter = {defecto:g}, máximo {maximo:g}): ")
    if total is not None and total > maximo:
        print(f"  Se pidió {total:g} s, pero el máximo es {maximo:g} s: se recorta.")
    semilla = leer_numero("  Semilla (Enter = al azar; repite una ejecución anterior con su semilla): ")
    semilla = None if semilla is None else int(semilla)
    plan = planificar_aleatorio(config, total, semilla)   # se muestra antes de confirmar
    print(describir_plan(plan))
    tamanos = verificar_servidor(config)
    print(f"  Servidor de PC1 correcto: {parametros['archivo_grande']} = {tamanos['archivo_grande']:,} B.")
    if not confirmar_ataque(ip, "escenario aleatorio con episodios anómalos"):
        print("  Cancelado.")
        return
    print("  (Ctrl+C para detenerlo; los tramos ya hechos quedan registrados)")
    filas = ejecutar_escenario_aleatorio(config, plan["total"], plan["semilla"], mostrar_plan=False)
    print(f"\n  Escenario aleatorio terminado (semilla {plan['semilla']}): {len(filas)} tramos registrados "
          f"en {ruta_registro(config)}.")


def opcion_ver_registro(config: dict) -> None:
    ruta = ruta_registro(config)
    filas = leer_ultimos_escenarios(ruta, 10)
    if not filas:
        print(f"  Aún no hay escenarios registrados en {ruta}.")
        return
    print(f"  Últimos {len(filas)} escenarios ({ruta}):")
    for fila in filas:
        print(f"  - {fila['fecha_hora_inicio']} -> {fila['fecha_hora_fin']} | {fila['tipo_escenario']} "
              f"| {fila['ip_destino']} | {fila['parametros']}")


ACCIONES = {"1": opcion_trafico_normal, "2": opcion_escaneo, "3": opcion_rafaga, "4": opcion_mixto,
            "5": opcion_aleatorio, "6": opcion_ver_registro}


def main() -> None:
    # Evita que la consola de Windows (cp1252) se caiga con caracteres no soportados.
    for flujo in (sys.stdout, sys.stderr):
        try:
            flujo.reconfigure(errors="replace")
        except AttributeError:
            pass
    analizador = argparse.ArgumentParser(description="Menú del generador de tráfico de PC2.")
    analizador.add_argument("--config", default=str(CARPETA / "configuracion.yaml"),
                            help="ruta a configuracion.yaml")
    ruta_config = analizador.parse_args().config

    while True:
        print(OPCIONES)
        try:
            opcion = input("Elige una opción: ").strip()
        except EOFError:
            opcion = "7"
        if opcion == "7":
            print("Hasta luego.")
            return
        accion = ACCIONES.get(opcion)
        if accion is None:
            print("  Opción no válida.")
            continue
        try:
            # Se recarga en cada opción para tomar cambios del YAML sin reiniciar.
            accion(cargar_configuracion(ruta_config))
        except ErrorConfiguracion as error:
            print(f"  No se ejecutó el escenario: {error}")
        except KeyboardInterrupt:
            print("\n  Escenario cancelado por el usuario (no se registró).")
        except EOFError:
            print("\n  Entrada terminada.")
            return
        except OSError as error:
            print(f"  Error de red o del sistema: {error}")


if __name__ == "__main__":
    main()
