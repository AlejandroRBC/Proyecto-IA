"""Pruebas del escenario aleatorio: planificación (pura) y ejecución con red simulada."""

import csv
import json
import threading
import time

import pytest

from generador_trafico.configuracion import ErrorConfiguracion, validar_parametros_aleatorio
from generador_trafico.escenario_aleatorio import ejecutar_escenario_aleatorio, planificar_aleatorio
from generador_trafico.escenario_mixto import TIPO_ANOMALO, TIPO_NORMAL


def _config(tmp_path=None, **aleatorio):
    al = {"duracion_total_segundos": 300, "normal_al_inicio_y_final_segundos": 20,
          "pausa_entre_episodios_segundos": [20, 60], "duracion_episodio_segundos": [5, 20],
          "descargas_paralelas": [1, 3],
          "pesos_tipo_episodio": {"descargas": 0.5, "descargas_y_rafaga": 0.3, "rafaga": 0.2},
          "semilla": None}
    al.update(aleatorio)
    config = {
        "red": {"ip_destino_pc1": "127.0.0.1"},
        "mixto": {"duracion_total_segundos": 300, "duracion_total_maxima_segundos": 900,
                  "proporciones": [0.4, 0.2, 0.4], "archivo_normal": "/prueba.txt",
                  "archivo_grande": "/grande.bin", "descargas_paralelas": 2,
                  "pausa_normal_min_segundos": 0.01, "pausa_normal_max_segundos": 0.02,
                  "pausa_anomala_segundos": 0.01},
        "aleatorio": al,
        "rafagas": {"duracion_maxima_segundos": 30, "conexiones_por_segundo": 20,
                    "puerto_destino": 8080, "concurrencia": 2},
        "registro": {"ruta_csv": "escenarios.csv"},
    }
    if tmp_path is not None:
        config["_carpeta_base"] = str(tmp_path)
    return config


def acciones_falsas(llamadas):
    candado = threading.Lock()

    def anotar(nombre):
        with candado:
            llamadas.append((time.monotonic(), nombre))

    def rafaga(segundos, detener):
        anotar("rafaga")
        detener.wait(min(segundos, 30))
        return {"intentos": 3}

    return {"ping": lambda: anotar("ping") or True, "get_normal": lambda: anotar("get_normal"),
            "get_grande": lambda: anotar("get_grande"), "rafaga": rafaga}


# ---------- Planificación ----------

def prueba_misma_semilla_mismo_plan_y_distinta_semilla_otro_plan():
    a = planificar_aleatorio(_config(), semilla=7)
    assert a == planificar_aleatorio(_config(), semilla=7)
    assert a["episodios"] != planificar_aleatorio(_config(), semilla=8)["episodios"]


@pytest.mark.parametrize("semilla", range(30))
def prueba_episodios_respetan_margenes_rangos_y_no_se_solapan(semilla):
    plan = planificar_aleatorio(_config(), semilla=semilla)
    eps = plan["episodios"]
    assert eps, "con 300 s siempre cabe al menos un episodio"
    assert eps[0]["inicio"] >= 20 and eps[-1]["inicio"] + eps[-1]["duracion"] <= 300 - 20 + 0.01
    for ep in eps:
        assert 5 <= ep["duracion"] <= 20
        assert ep["tipo"] in ("descargas", "descargas_y_rafaga", "rafaga")
        assert (ep["descargas_paralelas"] == 0) == (ep["tipo"] == "rafaga")
        assert ep["tipo"] == "rafaga" or 1 <= ep["descargas_paralelas"] <= 3
    for anterior, siguiente in zip(eps, eps[1:]):
        hueco = siguiente["inicio"] - (anterior["inicio"] + anterior["duracion"])
        assert 20 - 0.02 <= hueco <= 60 + 0.02


def prueba_los_episodios_varian_entre_ejecuciones():
    """Lo que pidió el usuario: no siempre lo mismo en el mismo momento."""
    planes = [planificar_aleatorio(_config(), semilla=s) for s in range(20)]
    assert len({len(p["episodios"]) for p in planes}) > 1
    assert len({p["episodios"][0]["inicio"] for p in planes}) == 20
    assert {ep["tipo"] for p in planes for ep in p["episodios"]} == {"descargas", "descargas_y_rafaga", "rafaga"}


def prueba_pesos_cero_excluyen_un_tipo():
    config = _config(pesos_tipo_episodio={"descargas": 1, "rafaga": 0})
    tipos = {ep["tipo"] for s in range(20) for ep in planificar_aleatorio(config, semilla=s)["episodios"]}
    assert tipos == {"descargas"}


def prueba_duracion_corta_tiene_un_episodio_y_se_recorta_al_maximo():
    corto = planificar_aleatorio(_config(), total=30, semilla=1)
    assert len(corto["episodios"]) == 1
    assert planificar_aleatorio(_config(), total=10**6, semilla=1)["total"] == 900


@pytest.mark.parametrize("cambio", [
    {"pausa_entre_episodios_segundos": [60, 20]}, {"duracion_episodio_segundos": [5]},
    {"pesos_tipo_episodio": {"otro": 1}}, {"pesos_tipo_episodio": {"descargas": 0}},
    {"descargas_paralelas": [0, 3]}, {"semilla": "abc"}, {"duracion_total_segundos": 5000},
])
def prueba_rechaza_configuracion_invalida(cambio):
    with pytest.raises(ErrorConfiguracion):
        validar_parametros_aleatorio(_config(**cambio))


# ---------- Ejecución con red simulada ----------

def prueba_normal_continuo_y_episodios_registrados(tmp_path):
    config = _config(tmp_path, normal_al_inicio_y_final_segundos=0.4, pausa_entre_episodios_segundos=[0.3, 0.4],
                     duracion_episodio_segundos=[1.2, 1.3], pesos_tipo_episodio={"descargas_y_rafaga": 1})
    llamadas = []
    inicio = time.monotonic()
    filas = ejecutar_escenario_aleatorio(config, total=4, semilla=3, acciones=acciones_falsas(llamadas),
                                         intervalo_progreso=100)
    assert time.monotonic() - inicio < 7
    tipos = [f["tipo_escenario"] for f in filas]
    assert tipos[0] == TIPO_NORMAL and tipos[-1] == TIPO_NORMAL and TIPO_ANOMALO in tipos
    assert all(a != b for a, b in zip(tipos, tipos[1:]))          # tramos alternados
    episodios = [f for f in filas if f["tipo_escenario"] == TIPO_ANOMALO]
    assert all(e["parametros"]["descargas_grandes"] > 0 and e["parametros"]["rafagas"] >= 1 for e in episodios)
    # El tráfico normal sigue durante los episodios.
    assert all(e["parametros"]["trafico_normal_simultaneo"].get("pings", 0) > 0 for e in episodios)
    # Las descargas grandes solo ocurren dentro de los episodios.
    grandes = [t - inicio for t, n in llamadas if n == "get_grande"]
    assert grandes and min(grandes) >= 0.4 - 0.05

    with open(tmp_path / "escenarios.csv", newline="", encoding="utf-8") as f:
        registradas = list(csv.DictReader(f))
    assert [r["tipo_escenario"] for r in registradas] == tipos
    assert all(json.loads(r["parametros"])["semilla"] == 3 for r in registradas)
    assert all(a["fecha_hora_fin"] <= b["fecha_hora_inicio"] for a, b in zip(registradas, registradas[1:]))


def prueba_episodio_solo_rafaga_no_descarga(tmp_path):
    config = _config(tmp_path, normal_al_inicio_y_final_segundos=0.3, duracion_episodio_segundos=[1.2, 1.2],
                     pesos_tipo_episodio={"rafaga": 1})
    llamadas = []
    ejecutar_escenario_aleatorio(config, total=2, semilla=1, acciones=acciones_falsas(llamadas),
                                 intervalo_progreso=100)
    nombres = {n for _, n in llamadas}
    assert "rafaga" in nombres and "get_grande" not in nombres
