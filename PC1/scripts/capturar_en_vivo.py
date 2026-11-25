"""Captura en vivo en PC1: convierte el tráfico real en flujos y los evalúa con el modelo.

Requisitos: Npcap instalado (https://npcap.com) y scapy (pip install -r requirements.txt).
Si Npcap se instaló con "Restrict Npcap driver's access to Administrators only",
hay que abrir la terminal como administrador.

Ejemplos (desde PC1/):
    python scripts/capturar_en_vivo.py                     # solo tráfico con PC2 (captura.ip_pc2)
    python scripts/capturar_en_vivo.py --ip-pc2 192.168.1.20
    python scripts/capturar_en_vivo.py --todo-el-trafico   # todo lo que pase por la interfaz
    python scripts/capturar_en_vivo.py --listar-interfaces
    python scripts/capturar_en_vivo.py --duracion 60 --solo-alertas
    python scripts/capturar_en_vivo.py --modelo laboratorio   # usar el modelo de laboratorio
    python scripts/capturar_en_vivo.py --todo-el-trafico --archivo-flujos datos/laboratorio/sesion1.csv

Mientras corre, el panel (streamlit run src/app/panel.py) muestra los flujos en
la sección "Monitoreo en vivo". Se detiene con Ctrl+C.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.captura.capturador import capturar, construir_filtro  # noqa: E402
from src.modelo.detector import MODELOS_DISPONIBLES, cargar_detector  # noqa: E402
from src.procesamiento.dataset import cargar_configuracion  # noqa: E402


def leer_argumentos(captura: dict) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Captura tráfico real y lo evalúa con el detector.")
    p.add_argument("--interfaz", default=captura.get("interfaz"),
                   help="Nombre de la interfaz (ej. Wi-Fi). Ver --listar-interfaces.")
    p.add_argument("--ip-pc2", default=captura.get("ip_pc2"), help="IP actual de PC2.")
    p.add_argument("--todo-el-trafico", action="store_true",
                   help="No filtrar por PC2: captura todo el tráfico IPv4 de la interfaz.")
    p.add_argument("--duracion", type=float, default=None,
                   help="Detenerse después de N segundos (por defecto, hasta Ctrl+C).")
    p.add_argument("--solo-alertas", action="store_true",
                   help="En consola mostrar solo flujos anómalos y no evaluables.")
    p.add_argument("--modelo", choices=MODELOS_DISPONIBLES, default=captura.get("modelo", "base"),
                   help="Modelo a usar: base (CICIDS2017) o laboratorio.")
    p.add_argument("--archivo-flujos", default=None,
                   help="Guardar las características de los flujos en este CSV en vez de "
                        "rutas.flujos_capturados (útil para separar sesiones de captura).")
    p.add_argument("--listar-interfaces", action="store_true", help="Mostrar interfaces y salir.")
    return p.parse_args()


def listar_interfaces() -> None:
    from scapy.all import conf

    print("Interfaces disponibles (usar el valor de la columna 'Nombre' en --interfaz):\n")
    print(f"  {'Nombre':<35} {'IPv4':<16} Descripción")
    for iface in conf.ifaces.values():
        print(f"  {iface.name:<35} {iface.ip or '-':<16} {iface.description}")


def main() -> None:
    config = cargar_configuracion()
    captura = config.get("captura") or {}
    args = leer_argumentos(captura)
    if args.listar_interfaces:
        listar_interfaces()
        return

    solo_pc2 = bool(captura.get("solo_trafico_pc2", True)) and not args.todo_el_trafico
    try:
        filtro = construir_filtro(args.ip_pc2, solo_pc2)
    except ValueError as e:
        sys.exit(str(e))

    try:
        detector = cargar_detector(config, args.modelo)
    except FileNotFoundError as e:
        sys.exit(str(e))
    rutas = dict(config["rutas"])
    if args.archivo_flujos:
        rutas["flujos_capturados"] = Path(args.archivo_flujos).resolve()
    print(f"Detector '{args.modelo}' cargado | umbral = {detector['umbral']:.6f}")
    print(f"Características de los flujos en: {rutas['flujos_capturados']}")
    print(f"Interfaz: {args.interfaz or '(predeterminada)'} | filtro: {filtro}")
    print("Capturando... (Ctrl+C para detener)\n")

    try:
        conteo = capturar(
            detector, rutas, args.interfaz, filtro,
            timeout_inactividad=float(captura.get("timeout_inactividad_segundos", 5)),
            timeout_activo=float(captura.get("timeout_activo_segundos", 120)),
            duracion=args.duracion, mostrar_normales=not args.solo_alertas,
        )
    except (RuntimeError, OSError, ValueError) as e:
        sys.exit(f"Error en la captura: {e}")

    print("\n=== Resumen ===")
    print(f"  Flujos evaluados: {sum(conteo.values())}")
    print(f"  Normales:         {conteo['NORMAL']}")
    print(f"  Anómalos:         {conteo['ANOMALO']}")
    print(f"  No evaluables:    {conteo['NO_EVALUABLE']}")


if __name__ == "__main__":
    main()
