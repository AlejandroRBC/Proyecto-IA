"""Pruebas del escenario mixto sin red: acciones de red reemplazadas por funciones falsas."""

import csv
import threading
import time

import pytest

from generador_trafico.configuracion import (
    LIMITE_ABSOLUTO_MIXTO_SEGUNDOS,
    ErrorConfiguracion,
    planificar_fases,
    validar_parametros_mixto,
)
from generador_trafico.escenario_mixto import TIPO_ANOMALO, TIPO_NORMAL, ejecutar_escenario_mixto


def _config(tmp_path=None, **mixto):
    base = {"duracion_total_segundos": 300, "duracion_total_maxima_segundos": 900,
            "proporciones": [0.4, 0.2, 0.4], "archivo_normal": "/prueba.txt",
            "archivo_grande": "/grande.bin", "descargas_paralelas": 2,
            "pausa_normal_min_segundos": 0.01, "pausa_normal_max_segundos": 0.02,
            "pausa_anomala_segundos": 0.01, "incluir_rafaga": True}
    base.update(mixto)
    config = {"red": {"ip_destino_pc1": "127.0.0.1"}, "mixto": base,
              "rafagas": {"duracion_maxima_segundos": 30, "conexiones_por_segundo": 20,
                          "puerto_destino": 8080, "concurrencia": 2},
              "registro": {"ruta_csv": "escenarios.csv"}}
    if tmp_path is not None:
        config["_carpeta_base"] = str(tmp_path)
    return config


class AccionesFalsas:
    """Registra qué acción se llamó y en qué fase (según el instante)."""

    def __init__(self):
        self.llamadas = []
        self.candado = threading.Lock()
        self.duraciones_rafaga = []

    def _anotar(self, nombre):
        with self.candado:
            self.llamadas.append(nombre)

    def como_dict(self):
        def rafaga(segundos, detener):
            self._anotar("rafaga")
            self.duraciones_rafaga.append(segundos)
            fin = time.monotonic() + min(segundos, 30)
            while time.monotonic() < fin and not detener.is_set():
                time.sleep(0.01)
            return {"intentos": 5}

        return {
            "ping": lambda: self._anotar("ping") or True,
            "get_normal": lambda: self._anotar("get_normal"),
            "get_grande": lambda: self._anotar("get_grande"),
            "rafaga": rafaga,
        }


# ---------- Planificación y validación ----------

def prueba_fases_por_defecto_son_120_60_120():
    assert planificar_fases(_config()) == [("normal_inicial", 120.0), ("anomala", 60.0), ("normal_final", 120.0)]


def prueba_duracion_pedida_se_recorta_al_maximo():
    fases = planificar_fases(_config(), total=5000)
    assert sum(s for _, s in fases) == pytest.approx(900)
    fases = planificar_fases(_config(duracion_total_maxima_segundos=LIMITE_ABSOLUTO_MIXTO_SEGUNDOS), total=10**6)
    assert sum(s for _, s in fases) == pytest.approx(LIMITE_ABSOLUTO_MIXTO_SEGUNDOS)


@pytest.mark.parametrize("cambio", [
    {"proporciones": [0.5, 0.5]}, {"proporciones": [0.5, 0.3, 0.3]}, {"proporciones": [1, 0, 0]},
    {"duracion_total_maxima_segundos": LIMITE_ABSOLUTO_MIXTO_SEGUNDOS + 1},
    {"duracion_total_segundos": 1000},                    # mayor que la máxima (900)
    {"descargas_paralelas": 0}, {"pausa_normal_min_segundos": 5, "pausa_normal_max_segundos": 1},
    {"archivo_grande": ""},
])
def prueba_rechaza_parametros_invalidos(cambio):
    with pytest.raises(ErrorConfiguracion):
        validar_parametros_mixto(_config(**cambio))


def prueba_duracion_cero_o_negativa():
    with pytest.raises(ErrorConfiguracion):
        planificar_fases(_config(), total=0)


def prueba_no_arranca_sin_ip_de_pc1():
    config = _config()
    config["red"]["ip_destino_pc1"] = ""
    with pytest.raises(ErrorConfiguracion):
        ejecutar_escenario_mixto(config, total=1, acciones=AccionesFalsas().como_dict(), registrar=False)


# ---------- Ejecución con red simulada ----------

def prueba_fases_hacen_lo_que_deben_y_se_registran(tmp_path):
    falsas = AccionesFalsas()
    inicio = time.monotonic()
    # Fase anómala de 1,4 s: la ráfaga solo arranca si a la fase le queda más de 1 s.
    filas = ejecutar_escenario_mixto(_config(tmp_path, proporciones=[0.15, 0.7, 0.15]), total=2,
                                     acciones=falsas.como_dict(), intervalo_progreso=100)
    assert time.monotonic() - inicio < 4
    assert [f["tipo_escenario"] for f in filas] == [TIPO_NORMAL, TIPO_ANOMALO, TIPO_NORMAL]
    normal, anomala, final = (f["parametros"] for f in filas)
    assert normal["pings"] > 0 and normal["descargas_pequenas"] > 0 and "descargas_grandes" not in normal
    assert anomala["descargas_grandes"] > 0 and "pings" not in anomala
    assert final["pings"] > 0 and not any(f["parametros"]["interrumpida"] for f in filas)
    # La ráfaga nunca recibe más tiempo del que le queda a la fase anómala (1,4 s).
    assert falsas.duraciones_rafaga and max(falsas.duraciones_rafaga) <= 1.41
    assert anomala["rafagas"] >= 1

    with open(tmp_path / "escenarios.csv", newline="", encoding="utf-8") as archivo:
        registradas = list(csv.DictReader(archivo))
    assert [r["tipo_escenario"] for r in registradas] == [TIPO_NORMAL, TIPO_ANOMALO, TIPO_NORMAL]
    assert all(r["ip_destino"] == "127.0.0.1" and r["ip_origen"] == "127.0.0.1" for r in registradas)
    assert registradas[0]["fecha_hora_fin"] <= registradas[1]["fecha_hora_inicio"]


def prueba_sin_rafaga_solo_descargas(tmp_path):
    falsas = AccionesFalsas()
    ejecutar_escenario_mixto(_config(tmp_path, incluir_rafaga=False), total=0.6,
                             acciones=falsas.como_dict(), intervalo_progreso=100)
    assert "rafaga" not in falsas.llamadas and "get_grande" in falsas.llamadas


def prueba_errores_de_red_no_detienen_el_escenario(tmp_path):
    def falla():
        raise ConnectionRefusedError("sin servidor")

    acciones = AccionesFalsas().como_dict() | {"get_normal": falla, "get_grande": falla}
    filas = ejecutar_escenario_mixto(_config(tmp_path, incluir_rafaga=False), total=0.6, acciones=acciones,
                                     intervalo_progreso=100)
    assert len(filas) == 3 and all(f["parametros"].get("errores", 0) > 0 for f in filas)


def prueba_menu_compila_y_tiene_la_opcion_mixta():
    """menu.py no lo importa ninguna otra prueba: al menos se comprueba que compila."""
    import py_compile
    from pathlib import Path

    ruta = Path(__file__).resolve().parents[1] / "menu.py"
    py_compile.compile(str(ruta), doraise=True)
    texto = ruta.read_text(encoding="utf-8")
    assert '"4": opcion_mixto' in texto and "6. Salir" in texto
