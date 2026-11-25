# CyberGuard AI — PC1

Detección de anomalías en tráfico de red con aprendizaje **no supervisado**
(`IsolationForest`), entrenado solo con tráfico normal y evaluado con CICIDS2017.

Esta tarea cubre únicamente el pipeline **datos → entrenamiento → evaluación**.
El sistema no clasifica tipos de ataque, no asigna gravedad, no bloquea conexiones
y no ejecuta respuestas automáticas.

## Estructura

```
PC1/
├── configuracion.yaml        # rutas, archivos, características, hiperparámetros, umbral
├── requirements.txt
├── pytest.ini                # permite que pytest encuentre prueba_*.py
├── datos/procesados/         # (ignorado por git) reservado
├── datos/en_vivo/            # (ignorado por git) alertas.csv generado por la demo
├── modelos/                  # (ignorado por git) modelo .joblib + metadatos .json
├── reportes/                 # metricas.csv, metricas_por_tipo.csv
│   └── figuras/              # (ignorado por git) distribucion_puntajes.png
├── src/
│   ├── procesamiento/        # dataset.py (carga) y caracteristicas.py (limpieza)
│   ├── modelo/               # entrenar.py, evaluar.py y detector.py
│   ├── alertas/              # gestor_alertas.py
│   ├── captura/              # pendiente, fase siguiente
│   └── app/                  # pendiente, fase siguiente
├── scripts/
│   ├── ejecutar_experimentos.py   # entrenamiento + evaluación
│   └── reproducir_flujos.py       # demo de monitoreo simulado
└── pruebas/                  # pruebas con pytest y datos simulados
```

Los CSV de CICIDS2017 deben estar en `../Datasets` (un nivel arriba de `PC1/`).

## Instalación

Desde la carpeta `PC1/`:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Ejecución

Desde `PC1/`:

```powershell
python scripts/ejecutar_experimentos.py   # verificación + entrenamiento + evaluación
```

O por partes:

```powershell
python -m src.modelo.entrenar
python -m src.modelo.evaluar
pytest                                     # pruebas básicas
```

Las rutas de `configuracion.yaml` se resuelven respecto a la carpeta del propio
YAML, así que los scripts funcionan aunque se lancen desde otro directorio.

**Codificación:** si la lectura de un CSV falla con `UnicodeDecodeError`, cambia
`datos.codificacion` de `utf-8` a `latin1` en `configuracion.yaml`.

## Metodología

| Paso | Detalle |
|---|---|
| Entrenamiento | Solo filas `BENIGN` de `Monday-WorkingHours.pcap_ISCX.csv` |
| División | 80 % entrenamiento / 20 % validación (ambas benignas), `random_state=42` |
| Características | 10 columnas en orden fijo (ver `configuracion.yaml`); `Label` nunca entra al modelo |
| Limpieza | `.str.strip()` en nombres → numérico → ±infinito a NaN → eliminar NaN → eliminar duplicados exactos **sobre las 10 características** |
| Modelo | `IsolationForest(n_estimators=200, max_samples=256, max_features=1.0, contamination="auto", random_state=42)` |
| Umbral | Percentil 1 de `decision_function` en validación (≈1 % de falsos positivos). Un flujo es anómalo si `decision_function < umbral` |
| Evaluación | Los 7 archivos de martes a viernes, usados una sola vez y sin ajustar nada con ellos |

Notas sobre la limpieza:
- En la evaluación los duplicados también se eliminan solo sobre las 10 características.
  Si dos flujos tienen las mismas características pero distinta etiqueta, se conserva el primero.
- La versión del dataset usada (MachineLearningCVE) no trae columnas de IP ni Timestamp.

### Verificación de columnas (Fase 1)

Las 10 características y `Label` existen con los nombres exactos en los 8 CSV
después de aplicar `.str.strip()`; los 8 archivos tienen 79 columnas. No hubo que
renombrar nada. Todos se leen correctamente en `utf-8`.

## Qué significan las métricas

Se toma el ataque como clase positiva: `BENIGN` = normal (0) y cualquier otro `Label` = anómalo (1).

- **Precision**: de los flujos marcados como anómalos, qué fracción eran ataques de verdad.
- **Recall**: de los ataques reales, qué fracción se marcó como anómala.
- **F1**: media armónica de Precision y Recall.
- **FPR**: fracción de flujos benignos marcados como anómalos (falsas alarmas).
- **ROC-AUC**: no depende del umbral. Mide qué tan bien el puntaje ordena los ataques
  por delante del tráfico normal: 0.5 es el azar y 1.0 la separación perfecta.
- **metricas_por_tipo.csv**: para cada valor de `Label`, la fracción de flujos marcados
  como anómalos. En los ataques es su recall y en `BENIGN` es el FPR. Sirve solo
  para analizar; el sistema no clasifica tipos.

## Resultados de la línea base

| Métrica | Valor |
|---|---|
| Umbral (`decision_function`) | −0.157354 |
| FPR en validación | 1.00 % |
| Precision | 0.0073 |
| Recall | 0.0003 |
| F1 | 0.0006 |
| FPR en evaluación | 1.22 % |
| ROC-AUC | 0.695 |

La configuración base **casi no detecta ataques** con un umbral de 1 % de FPR.
En `reportes/figuras/distribucion_puntajes.png` se ve que los ataques sí tienen
puntajes más bajos que el pico principal del tráfico benigno, pero el tráfico benigno
del lunes tiene una cola larga de puntajes bajos. Por eso el umbral del 1 % queda a la
izquierda de casi todos los ataques. Solo destacan Heartbleed (100 %) e Infiltration (33 %).

Mejorar esto requiere una decisión metodológica, por ejemplo transformar las
características (`log1p`), agregar otras o fijar otro FPR objetivo por política.
Esa decisión debe justificarse **sin** usar los archivos de evaluación. Si no,
hay fuga de datos.

## Experimento: log1p en características de volumen y tasa

Este experimento prueba si aplicar `np.log1p` mejora la separación entre tráfico normal
y anómalo. Se aplica a `Flow Duration`, `Total Length of Fwd/Bwd Packets`, `Flow Bytes/s`,
`Flow Packets/s` y `Flow IAT Mean`. Los conteos, `SYN Flag Count` y `Destination Port` no se
transforman. Antes de la transformación se eliminan las filas con valores negativos en esas
columnas, que CICIDS2017 trae por errores de cálculo.

```powershell
python scripts/experimento_log1p.py
```

- Usa `limpiar(..., aplicar_log1p=True)`. Por defecto (`False`) el pipeline base no cambia.
- La división, los hiperparámetros y la regla del umbral (1 % de FPR en su propia
  validación) son los mismos que en el modelo base. La evaluación se hizo una sola vez.
- Resultados en `modelos/log1p/` y `reportes/log1p/` (los dos están en `.gitignore`).
  La comparación con el modelo base está en `reportes/log1p/comparacion.md`.
- El modelo log1p **no** es compatible con `detector.py`, porque espera las características
  ya transformadas.

**Estado: decisión pendiente.** No se ha decidido si log1p se adopta como pipeline oficial.
En la única corrida, Infiltration pasó de 33 % a 42 % y el ROC-AUC de 0.695 a 0.702. Los
ataques de volumen siguieron en 0 % y el FPR en evaluación subió de 1.22 % a 1.47 %.

## Detector y alertas

### Detector (`src/modelo/detector.py`)

Aplica a flujos nuevos el modelo y el umbral guardados en `modelos/`.

- `cargar_detector(config)`: carga el modelo y los metadatos una sola vez y devuelve
  `orden_columnas` y `umbral`.
- `preparar_flujo_para_prediccion(datos, orden_columnas)`: acepta un `dict`, una `Series`
  o un DataFrame de una fila. Pasa los valores a numérico, convierte los infinitos en NaN
  y devuelve un DataFrame en orden fijo. Si falta una característica o un valor no es
  válido, devuelve `None`.
- `evaluar_flujo(detector, datos)`: devuelve `{"resultado", "score", "umbral"}`, donde
  `resultado` es `NORMAL`, `ANOMALO` o `NO_EVALUABLE`. Un flujo inválido no lanza error
  ni se evalúa como si fuera válido.
- `evaluar_lote(detector, df)`: agrega `resultado`, `score` y `umbral` a cada fila y
  conserva las demás columnas.

**Por qué se separan características e identificación.** Al modelo solo entran las 10
características. Los campos `id_flujo`, `ip_origen`, `ip_destino`, `puerto_origen` y
`puerto_destino` solo se usan para mostrar la alerta. Así el modelo no puede aprender
de una IP concreta, y el detector ya está listo para cuando la captura real traiga IPs.
Por ahora el dataset no las trae y esos campos quedan vacíos.

A diferencia de `limpiar()`, que se usa en entrenamiento y evaluación, el detector
**no elimina duplicados** ni descarta filas en silencio.

### Gestor de alertas (`src/alertas/gestor_alertas.py`)

- `registrar_alerta(ruta_csv, info)`: agrega una fila al CSV de alertas. Crea la carpeta
  y el encabezado si no existen y usa la hora actual si no se le pasa `fecha_hora`.
- `procesar_resultado(ruta_csv, fila_evaluada)`: escribe la fila **solo si
  `resultado == "ANOMALO"`**.

`datos/en_vivo/alertas.csv` (ruta definida en `configuracion.yaml`) **registra solo
anomalías, no todo el tráfico**. Sus columnas son `fecha_hora, id_flujo, ip_origen,
ip_destino, puerto_origen, puerto_destino, score, umbral, resultado`.

### Demo: monitoreo simulado (`scripts/reproducir_flujos.py`)

Mientras no exista la captura real, este script reproduce una muestra pequeña de
flujos de los CSV, fila por fila y con una pausa entre ellos:

```powershell
python scripts/reproducir_flujos.py --origen ../Datasets/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv --filas 50
python scripts/reproducir_flujos.py                      # por defecto: lunes + PortScan, 25 de cada uno
python scripts/reproducir_flujos.py --filas 300 --intervalo-segundos 0 --limpiar-alertas
```

| Opción | Qué hace |
|---|---|
| `--origen` | Uno o más CSV, como ruta o como nombre dentro de `../Datasets` |
| `--filas` | Flujos por archivo. Por defecto es una muestra aleatoria con semilla; `--primeras` toma las primeras N |
| `--intervalo-segundos` | Pausa entre flujos (0.5 s por defecto) |
| `--limpiar-alertas` | Borra `alertas.csv` antes de empezar |

- `id_flujo` es `<archivo>#<índice de la fila en el CSV>`.
- `ip_origen`, `ip_destino` y `puerto_origen` quedan vacíos porque el dataset no los trae.
- `puerto_destino` toma el valor de `Destination Port`, que sí existe. No se usa como
  `puerto_origen` porque significaría otra cosa.
- La consola muestra el `Label` real solo como referencia; el modelo nunca lo recibe.

Con el modelo de línea base, la demo casi no genera alertas de PortScan, porque su
recall en la evaluación fue de 0 %. Para que el sistema sirva en la demostración primero
hay que mejorar el modelo (ver "Resultados de la línea base").

## Panel Streamlit (`src/app/panel.py`)

Desde `PC1/`:

```powershell
streamlit run src/app/panel.py
```

El panel **no carga el modelo ni calcula puntajes**. Lee los CSV que ya existen y lanza
`reproducir_flujos.py` como subproceso, que es el que usa `detector.py`. La lógica sin
interfaz (lectura de CSV, comando, conteos y gráfica) está en `src/app/datos_panel.py`.

| Sección | Qué muestra |
|---|---|
| **Lanzar monitoreo** (barra lateral) | Elige uno de los 8 CSV, filtra opcionalmente por `Label`, y fija la cantidad de flujos (50 por defecto), el intervalo (0 s por defecto) y la semilla. **Iniciar monitoreo** corre la demo y deja su salida de consola en un desplegable. **Limpiar historial** borra `alertas.csv` y `flujos_analizados.csv`, solo después de marcar la casilla de confirmación. |
| **Estado del modelo** | Precision, Recall, F1, FPR y ROC-AUC de `reportes/metricas.csv`, y `metricas_por_tipo.csv` ordenado por recall, junto con la limitación conocida del modelo. |
| **Monitoreo actual** | Conteo de flujos normales, anómalos y no evaluables, una gráfica del puntaje de cada flujo con la línea del umbral oficial, y las últimas alertas (las más recientes primero). |
| **Explorador de umbral** | Un slider para un umbral hipotético que recalcula en memoria cuántos flujos del historial quedarían como anómalos. **Es solo visualización: no cambia el umbral oficial ni las alertas guardadas.** |

**Historial completo.** Desde esta fase, `reproducir_flujos.py` también escribe
`datos/en_vivo/flujos_analizados.csv` con todos los flujos evaluados (columnas
`fecha_hora, id_flujo, archivo_origen, puerto_destino, score, umbral, resultado`).
`alertas.csv` sigue guardando solo las anomalías. Para desactivar el historial completo:
`--sin-historial-completo`.

**Para la exposición.** Una muestra aleatoria casi nunca incluye ataques raros. Por
ejemplo, Heartbleed son 11 filas entre 692 mil del miércoles. Para ver alertas reales:

1. Limpia el historial.
2. Corre unos 60 flujos de **Wednesday** con *Todas*, para que se vea el tráfico normal.
3. Corre **Wednesday** + **Heartbleed**: 11 de 11 quedan bajo el umbral.
4. Opcional: **Thursday-…-Infilteration** + **Infiltration**: 12 de 36 quedan bajo el umbral.

El historial se acumula entre corridas, así que la gráfica muestra las tres fases seguidas.
Desde consola, lo mismo se hace con `--etiqueta Heartbleed`.

**Colores de la gráfica.** Azul para el puntaje, rojo con marcador X para lo anómalo y
amarillo para el umbral hipotético. Están validados para daltonismo, y la forma del
marcador y las etiquetas de texto hacen que no dependan solo del color.

## Reproducibilidad

Todas las semillas están fijas (`random_state=42`). Correr el pipeline dos veces da
el mismo umbral y las mismas métricas. Solo cambia `fecha_entrenamiento` en los metadatos.

## Pendiente (no incluido en esta tarea)

- **Captura real con CICFlowMeter/Npcap** (`src/captura/`): reemplazará a
  `reproducir_flujos.py` como fuente de flujos. Usará las mismas funciones
  `preparar_flujo_para_prediccion` y `evaluar_flujo`, y llenará los campos de IP.
- **PC2**: no se desarrolla aquí.
