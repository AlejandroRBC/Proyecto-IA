# Guía de demostración completa: del entrenamiento al tráfico de PC2 en el panel de PC1

Esta guía recorre todo lo que hace el sistema, en el orden en que conviene mostrarlo:
entrenar el modelo, comprobar que detecta, generar tráfico real desde PC2, verlo en el
panel de PC1 y guardar el resultado.

- **PC1**: modelo, captura, panel Streamlit y análisis (carpeta `PC1/`).
- **PC2**: generador de tráfico por consola (carpeta `PC2/`).
- IPs de las pruebas: **PC1 = 192.168.1.7**, **PC2 = 192.168.1.10** (pueden cambiar).

> Cada parte se puede mostrar por separado. Si no hay tiempo, lo esencial es la
> **Parte 4** (demo en vivo con PC2) y la **Parte 5** (guardar el resultado).

```
Parte 1  Entrenar y evaluar el modelo            PC1
Parte 2  Demo simulada con el dataset            PC1   (sin PC2, sin red)
Parte 3  Preparar las dos máquinas               PC1 + PC2
Parte 4  Demo en vivo: PC2 genera, PC1 detecta   PC1 + PC2
Parte 5  Guardar y analizar la sesión            PC1
Parte 6  (Opcional) Modelo de laboratorio        PC1 + PC2
Parte 7  Cierre y limpieza
```

---

## Parte 1. Entrenar y evaluar el modelo (PC1)

Requiere los CSV de CICIDS2017 en `Datasets/` (no se suben a git).

```
cd PC1
.venv\Scripts\activate
pip install -r requirements.txt
python scripts/ejecutar_experimentos.py
```

Qué hace, en orden:

1. Verifica que las 10 características y la etiqueta existen en los 8 CSV.
2. Limpia los datos (números, infinitos, vacíos, duplicados).
3. **Entrena solo con tráfico BENIGN del lunes** (459.582 filas: 80 % entrenamiento,
   20 % validación), `IsolationForest` con semilla 42.
4. **Calibra el umbral** con la validación: percentil 1 de los puntajes → **-0,157354**
   (el 1 % del tráfico normal queda por debajo).
5. **Evalúa una sola vez** con los 7 archivos de martes a viernes (1.817.947 flujos).

Qué debe verse y qué decir:

| Resultado | Valor |
|---|---|
| Umbral | -0,157354 |
| ROC-AUC | 0,695 |
| Heartbleed detectado | 100 % |
| Infiltration | 33 % |
| PortScan, DDoS, DoS | 0 % |

Mensaje clave: el modelo detecta anomalías **puntuales y raras**, pero no ataques de
volumen. Esos forman grupos de flujos parecidos entre sí y no se aíslan como raros. Es una
limitación del enfoque, no del umbral. Esto prepara lo que se verá en la Parte 4.

Salidas: `modelos/isolation_forest.joblib`, `modelos/metadatos_modelo.json`,
`reportes/metricas.csv` y `reportes/metricas_por_tipo.csv`.

Si el modelo ya está entrenado, este paso se puede saltar y solo mostrar los reportes.

Opcional, comprobar que el código funciona (no usa la red ni el dataset):

```
python -m pytest        # esperado: 69 pruebas pasan
```

---

## Parte 2. Demo simulada con el dataset (PC1, sin PC2)

Muestra el ciclo flujo → modelo → alerta antes de tener tráfico real.

```
streamlit run src/app/panel.py        # abrir http://localhost:8501
```

En la barra lateral, **Lanzar monitoreo**:

1. **Limpiar historial** (marcar la casilla de confirmación).
2. Archivo `Wednesday-workingHours…` + etiqueta **Heartbleed** → **Iniciar monitoreo**.
   Resultado esperado: **11 de 11 flujos anómalos** (el modelo sí los ve).
3. Archivo `Friday-…-PortScan…` → **Iniciar monitoreo**.
   Resultado esperado: **0 alertas**, coherente con su 0 % de recall.

Con esto queda a la vista el punto fuerte y la limitación antes de pasar al tráfico real.

---

## Parte 3. Preparar las dos máquinas

### 3.1 Red y datos (una sola vez)

1. PC1 y PC2 en la **misma red**, con perfil de red **Privada** en Windows.
2. IP de PC1: `ipconfig` en PC1 → IPv4 del Wi-Fi (por ejemplo `192.168.1.7`).
3. IP de PC2: `ipconfig` en PC2 (por ejemplo `192.168.1.10`).
4. **Hora sincronizada** en ambas (al minuto). Si no, como administrador: `w32tm /resync`.
5. **Permitir el ping** en PC1 (PowerShell como administrador):
   ```
   New-NetFirewallRule -DisplayName "Demo PC2 - ping" -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Allow
   ```

### 3.2 PC2: instalar y configurar

```
cd PC2
git pull
pip install -r requirements.txt
```

- Editar `PC2/configuracion.yaml`: `red.ip_destino_pc1: "192.168.1.7"` (la IP real de PC1).
- Para el escaneo: instalar **nmap** desde <https://nmap.org/download.html> y comprobar
  con `nmap --version`.
- Comprobar conectividad: `ping 192.168.1.7`.
- Las pruebas de PC2 no usan la red: `python -m pytest` (esperado: 110 pasan).

### 3.3 PC1: la IP de PC2

En `PC1/configuracion.yaml`, sección `captura`: `ip_pc2: "192.168.1.10"` (o pasarla
con `--ip-pc2` al capturar) e `interfaz: "Wi-Fi"`. Para ver las interfaces:

```
python scripts/capturar_en_vivo.py --listar-interfaces
```

Requiere **Npcap** instalado en PC1.

---

## Parte 4. Demo en vivo: PC2 genera tráfico, PC1 lo detecta

### 4.1 PC1: tres terminales (desde `PC1/`)

Antes de empezar, **cerrar cualquier `python -m http.server` abierto**: ocupan los puertos
8000 y 8080.

| Terminal | Comando | Para qué |
|---|---|---|
| 1 | `python scripts/servidor_demo.py` | Sirve `prueba.txt` (16 B) y `grande.bin` (256 KB) en los puertos 8000 y 8080 |
| 2 | `python scripts/capturar_en_vivo.py` | Captura el tráfico con PC2, arma flujos y los evalúa |
| 3 | `streamlit run src/app/panel.py` | Panel; abrir **http://localhost:8501** y bajar a **Monitoreo en vivo** |

La primera vez Windows pregunta por el firewall: **permitir en redes privadas**.
En el panel debe aparecer **«Captura activa con el modelo base»**.

### 4.2 PC2: el menú

```
cd PC2
python menu.py
```

Opciones, en el orden recomendado para mostrar:

| Paso | Opción | Qué responder | Qué debe verse en el panel de PC1 |
|---|---|---|---|
| 1 | **1** Tráfico normal | `s` a la descarga HTTP | Flujos **NORMAL** (ping y GET pequeños) |
| 2 | **2** Escanear puertos | `s` a la confirmación (opcional) | Muchos flujos de un solo paquete: **NO_EVALUABLE** o NORMAL; el modelo no ve el escaneo |
| 3 | **3** Ráfaga | Duración `10` y `s` | Cientos de flujos NORMAL: **no se detecta** |
| 4 | **4** Escenario mixto | Enter (300 s) y `s` | 2 min normal → 1 min **alertas** → 2 min normal |
| 5 | **5** Escenario aleatorio | Duración, semilla (Enter = al azar) y `s` | Normal continuo con **episodios de alertas** en momentos al azar |

Antes de los pasos 2 a 5, PC2 muestra la IP destino y pide confirmación: comprobar que es
la de PC1. En los pasos 4 y 5 además comprueba que PC1 sirve `grande.bin`; si no, se
detiene y dice qué hacer.

### 4.3 Qué mostrar y explicar

- **Descargas grandes (fase anómala):** aparecen como **X rojas** bajo el umbral y llenan
  «Alertas en vivo». Son transferencias rápidas y voluminosas, algo raro frente a lo normal.
- **Tráfico normal:** puntos azules sobre el umbral, sin alertas.
- **Ráfaga y escaneo:** no generan alertas. Cada conexión suelta parece normal; lo anómalo
  es **cuántas** llegan desde la misma IP en pocos segundos, y este modelo juzga cada flujo
  por separado. Mismo resultado que PortScan y DoS en CICIDS2017 (Parte 1).
- **Medidas de seguridad de PC2** (opcional mostrar): con `ip_destino_pc1: ""` se niega a
  ejecutar; con `"8.8.8.8"` rechaza la IP por ser pública; una ráfaga pedida de 120 s se
  recorta a 30 s.

El escenario aleatorio muestra una semilla; con la misma semilla se repite exactamente la
misma ejecución (útil para volver a mostrarlo igual).

### 4.4 Resultado esperado (medido el 25/11/2026, Wi-Fi, modelo base)

| Tráfico de PC2 | Marcados anómalos |
|---|---|
| Descarga pequeña (normal) | 0 % |
| Ping | 0 % |
| **Descarga grande (ataque simulado)** | **96 %** |
| Ráfaga | 0 % |

---

## Parte 5. Guardar y analizar la sesión (PC1)

Al terminar el escenario, parar la captura con **Ctrl+C** (terminal 2). Después, para
guardar los resultados con las gráficas:

1. Copiar `PC2/registros/escenarios_ejecutados.csv` a
   `PC1/datos/laboratorio/escenarios_pc2.csv` (opcional: permite resumir por tramo y
   dibujar los episodios).
2. En PC1:
   ```
   python scripts/analizar_sesion.py --desde "2026-11-25 16:40" --nombre mi_sesion --escenarios-pc2 datos/laboratorio/escenarios_pc2.csv
   ```
   (`--desde` = hora de inicio de la sesión, reloj de PC1; sin el CSV de PC2, quitar la
   última opción.)

Se crea `PC1/reportes/sesiones/mi_sesion/` con:

| Archivo | Contenido |
|---|---|
| `RESUMEN.md` | Resultado por tipo de tráfico, lectura y gráfica |
| `puntajes.png` | Puntaje de cada flujo en el tiempo, con el umbral y los episodios |
| `resumen_por_tipo.csv`, `resumen_por_tramo.csv` | Tablas |
| `metricas.json` | Precision, recall, FPR |
| `flujos.csv` | Todos los flujos de la sesión con su tipo de tráfico |

Cada flujo se clasifica por su **forma** (puerto y bytes), no por la hora, así que el
resultado no depende de que los relojes coincidan.

La sesión real del 25/11 ya está guardada en
`PC1/reportes/sesiones/2026-11-25_escenario_mixto/` por si hace falta mostrarla sin repetir
la demo.

---

## Parte 6. (Opcional) Modelo de laboratorio

El modelo base aprendió el tráfico normal de 2017. El de laboratorio repite la misma
metodología con tráfico normal **de tu red**. Requiere una sesión larga.

1. **PC1**, capturar todo el tráfico durante **15-20 minutos**:
   ```
   python scripts/capturar_en_vivo.py --todo-el-trafico
   ```
   Mientras tanto, usar PC1 con normalidad (navegar, descargar) y, desde PC2, ejecutar
   varias veces la opción 1 y, al final, las opciones 2, 3 y 4, con unos segundos entre
   escenarios.
2. Copiar `PC2/registros/escenarios_ejecutados.csv` a
   `PC1/datos/laboratorio/escenarios_pc2.csv`.
3. **Entrenar y comparar** (hacen falta al menos 200 flujos normales):
   ```
   python scripts/entrenar_modelo_laboratorio.py
   ```
   Cada flujo de PC2 se etiqueta según el escenario más cercano en el tiempo; el modelo
   se entrena **solo con los normales** y se compara con el modelo base sobre las mismas
   filas. Resultados en `reportes/laboratorio/` y en el panel («Estado del modelo»).
4. Usarlo en vivo:
   ```
   python scripts/capturar_en_vivo.py --modelo laboratorio
   ```

Aviso: en una prueba corta por loopback, ni el modelo base ni el de laboratorio detectaron
la ráfaga. Esta parte no está medida con datos reales; mostrarla como el siguiente paso.

---

## Parte 7. Cierre y limpieza

- Parar con Ctrl+C: captura, `servidor_demo.py` y el panel.
- Si se creó la regla del ping y ya no se quiere (PowerShell como administrador):
  ```
  Remove-NetFirewallRule -DisplayName "Demo PC2 - ping"
  ```
- Para repetir la demo desde cero: en el panel, **Limpiar historial**.

### Mensajes para cerrar la presentación

1. El modelo se entrena solo con tráfico normal y marca lo que se aleja de él.
2. Detecta bien las transferencias voluminosas (96 %) y no da falsos positivos con tráfico
   normal (0 %).
3. No detecta ráfagas ni escaneos, porque juzga cada flujo por separado.
4. Trabajo futuro: características por ventana de tiempo para cada IP (conexiones y puertos
   distintos en los últimos segundos) y modelo entrenado con el tráfico del laboratorio.

---

## Problemas frecuentes

| Síntoma | Causa probable | Solución |
|---|---|---|
| PC2: `Falta la IP de PC1` | `ip_destino_pc1` vacío | Completarlo en `PC2/configuracion.yaml` |
| Ping sin respuesta | Firewall de PC1 o redes distintas | Regla de la Parte 3.1, perfil Privada, misma red |
| PC2: `no entrega /grande.bin` o `mide solo N bytes` | `servidor_demo.py` no corre o hay otro `http.server` | Cerrar los `http.server` y ejecutar `servidor_demo.py` |
| `servidor_demo.py`: puerto ocupado | Otro servidor en 8000 u 8080 | Cerrarlo con Ctrl+C |
| El panel dice «La captura no está corriendo» | La captura se detuvo o no se inició | Ejecutar `capturar_en_vivo.py` y comprobar permisos y la interfaz |
| La captura no ve nada | Interfaz o `ip_pc2` incorrectas | `--listar-interfaces` y revisar `captura.ip_pc2` |
| Panel sin alertas aunque PC2 terminó | Se bajó un archivo pequeño o la captura estaba caída | Revisar que `servidor_demo.py` sea lo único en 8000/8080 y que la captura siga activa |
| `No se encontró nmap` | nmap no instalado o terminal abierta antes | Instalarlo y abrir una terminal nueva |
| El panel se ve en negro | Carga lenta o tema oscuro | Esperar unos segundos, recargar (F5) o usar http://127.0.0.1:8501 |

Más detalle en `PC2/GUIA_DEMO.md` y `PC1/README.md`.
