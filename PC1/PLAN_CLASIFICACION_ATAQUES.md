# Plan: clasificación de ataques (reglas por ventana + Random Forest CICIDS2017)

> **Estado: implementado el 25/11/2026.** Resultados en `reportes/clasificador/RESUMEN.md`.
> Cambios respecto al plan: los flujos «al revés» se orientan con el corte servicio < 10000 <=
> cliente, porque PC2 usa puertos efímeros 13000-19000. Las reglas no escriben una alerta por
> flujo: los ataques que el modelo no ve quedan como incidentes en `incidentes.csv`, con la
> columna «detectado por».

## Contexto
Hoy el sistema solo responde "anómalo o normal", flujo a flujo, con Isolation Forest. Por eso las ráfagas
y los escaneos pasan siempre como normales (0 %): cada conexión, vista sola, parece normal. El usuario
quiere que el sistema **diga qué ataque es**. Eligió **reglas + IA** y presenta **hoy a las 23:00**, así
que el orden de los pasos hace que lo esencial (reglas en vivo) funcione primero; el Random Forest va
después y, si no da tiempo, se queda como resultado fuera de línea.

Resultado esperado:
- Las reglas por ventana de tiempo e IP detectan y nombran **escaneo de puertos**, **ráfaga de conexiones
  (DoS)** y **transferencia masiva**, y así cubren el punto ciego del Isolation Forest.
- Un **Random Forest multiclase** entrenado con los ataques etiquetados de CICIDS2017 (los 8 CSV en
  `Datasets/`, con las mismas 10 características) es la parte de IA, con sus métricas y su matriz de
  confusión.
- En la consola de captura y en el panel aparecen **incidentes** con su tipo: uno por ataque y no miles
  de filas.

## Paso 1. Reglas por ventana (núcleo; va primero)
**Nuevo `PC1/src/clasificacion/reglas.py`** (funciones puras, sin red):
- `orientar(fila)`: devuelve atacante, víctima y puerto del servidor, y corrige los flujos "al revés"
  (SYN perdido) con la misma idea que `clasificar_trafico` en `src/analisis/sesion.py`.
- La clase `ClasificadorVentana` guarda, para cada IP atacante, un `deque` con los flujos de los últimos
  `ventana_segundos` (10 s, según `inicio_flujo`). Cuenta **todos** los flujos, también los NO_EVALUABLE:
  los sondeos de nmap `-sT` y las conexiones de la ráfaga son flujos de 1 o 2 paquetes.
- Reglas, con umbrales en `configuracion.yaml` (`clasificacion:`):
  - `escaneo_puertos`: al menos 15 puertos de destino distintos en la ventana.
  - `rafaga_conexiones`: al menos 50 conexiones TCP al mismo puerto en la ventana.
  - `transferencia_masiva`: el flujo es ANOMALO para el Isolation Forest y el servidor envió al menos
    20 KB, o la ventana suma al menos 5 MB.
  - Si es ANOMALO y no cumple ninguna regla: `anomalia_sin_clasificar` (se completa con el Random Forest
    en el paso 3).
- **Incidentes**: un incidente por (IP atacante, tipo). Mientras sigue activo se actualiza (última hora,
  flujos, puertos distintos, conexiones/s, bytes) y no se abre otro. Se cierra tras 30 s sin actividad.
  `procesar(filas) -> (filas con tipo_ataque, incidentes nuevos o actualizados)`.
- Se puede reproducir sobre un CSV ya guardado (ordenado por `inicio_flujo`) para validar sin red.

**Integración**
- `PC1/src/captura/capturador.py`, en `capturar().procesar`: después de `evaluar_flujos`, se llama a
  `clasificador.procesar(evaluados)`. Se añade `tipo_ataque` a cada fila, se escriben los incidentes y se
  imprime `[INCIDENTE] ESCANEO DE PUERTOS 192.168.1.10 -> 192.168.1.7: 120 puertos en 10 s`. El estado
  JSON gana el campo `incidentes`.
- `PC1/src/alertas/gestor_alertas.py`: se añade `tipo_ataque` a `COLUMNAS_ALERTA` y `COLUMNAS_HISTORIAL`
  (el respaldo automático `_respaldar_si_cambio_encabezado` ya se ocupa de los CSV viejos), y la función
  `registrar_incidente` escribe en `datos/en_vivo/incidentes.csv`, una fila por actualización y con
  `id_incidente`. El panel muestra la última fila de cada incidente.
- Las reglas también disparan una alerta aunque el Isolation Forest diga NORMAL: así las ráfagas y los
  escaneos aparecen por fin. El panel marca qué lo detectó (`modelo`, `reglas` o ambos).

## Paso 2. Panel y análisis de sesión
- `PC1/src/app/datos_panel.py`: añadir `leer_incidentes` y `resumen_incidentes` (última fila de cada
  incidente y conteo por tipo).
- `PC1/src/app/panel.py` (dentro de `seccion_en_vivo`, que ya se refresca con `st.fragment`): una tabla
  «Incidentes detectados» (tipo, atacante, inicio, duración, flujos, puertos y conexiones/s), métricas
  por tipo y la columna `tipo_ataque` en «Alertas en vivo».
- `PC1/src/analisis/sesion.py` y `scripts/analizar_sesion.py`: reproducir las reglas sobre los flujos de
  la sesión y añadir a `RESUMEN.md` la sección «Clasificación de ataques»: incidentes por tipo y cruce
  entre `tipo_trafico` y `tipo_ataque`.

## Paso 3. Random Forest multiclase (IA)
- Nuevo `PC1/src/clasificacion/modelo_ataques.py` y `PC1/scripts/entrenar_clasificador_ataques.py`:
  - Se carga con `cargar_csv` y las mismas `limpiar` / `seleccionar_caracteristicas` de
    `src/procesamiento/`. Las etiquetas se agrupan en familias: BENIGN, DoS (Hulk, GoldenEye, slowloris,
    Slowhttptest), DDoS, PortScan, Fuerza bruta (FTP/SSH-Patator), Ataque web (3 tipos) y Bot.
    Infiltration (36 flujos) y Heartbleed (11) quedan fuera porque hay demasiado pocos.
  - Submuestreo estratificado (máx. ~40 000 por familia, semilla 42) para entrenar en minutos;
    división 80/20 estratificada; `RandomForestClassifier(n_estimators=200, class_weight="balanced",
    n_jobs=-1)`.
  - Salidas: `modelos/clasificador/random_forest_ataques.joblib` con sus metadatos y, en
    `reportes/clasificador/`, `classification_report.csv`, `matriz_confusion.png` (con el skill dataviz)
    e `importancia_caracteristicas.csv`.
- En vivo, solo para flujos ANOMALO sin regla: `tipo_ataque = rf:<familia>` con su probabilidad. Si el
  Random Forest dice BENIGN, se queda `anomalia_sin_clasificar`. Las reglas tienen prioridad porque están
  medidas en el laboratorio.
- El panel, en «Estado del modelo», muestra la subsección «Clasificador de ataques (CICIDS2017)» con las
  métricas y la matriz.
- **Medición honesta**: se aplica el Random Forest a la sesión real ya guardada
  (`reportes/sesiones/2026-11-25_escenario_mixto/flujos.csv`) y se informa de lo que diga, aunque sea malo
  (cambio de dominio).

## Paso 4. Documentación y commit
- `PC1/RESUMEN_AVANCE.txt` y `GUIA_DEMOSTRACION_COMPLETA.md`: nueva sección (cómo se clasifica, qué debe
  verse en la demo y los límites de más abajo). En la guía, la opción 2 de PC2 (nmap `-sT`) queda como
  prueba del escaneo.
- Commit y push a `main` cuando el usuario lo pida.

## Límites (para la presentación y la documentación)
- **Cambio de dominio**: el Random Forest aprende del CICIDS2017 (otra red, del 2017, con CICFlowMeter).
  En el laboratorio sus etiquetas no son fiables, y por eso se mide y se prioriza a las reglas.
- **Solo se validan en vivo los ataques que PC2 puede generar** (escaneo, ráfaga y descarga masiva).
  DDoS real (hacen falta muchas fuentes), fuerza bruta, ataques web y botnets solo se evalúan con el
  dataset.
- Umbrales ajustados al laboratorio: en una red real, un navegador o una copia de seguridad pueden
  dispararlos, y un escaneo lento (1 puerto por minuto) pasa por debajo de la ventana.
- Solo se ven estadísticas de flujo: no hay inspección de contenido, así que el tráfico cifrado (HTTPS) y
  los ataques que imitan tráfico normal no se pueden distinguir.
- Atribución por IP: la suplantación de IP (spoofing) o el NAT la confunden.
- Npcap pierde paquetes con mucho volumen en Wi-Fi.
- Los ataques nuevos (zero-day) solo salen como `anomalia_sin_clasificar`.

## Verificación
1. Pruebas nuevas `PC1/pruebas/prueba_clasificacion.py` con flujos sintéticos: escaneo (20 puertos en
   5 s), ráfaga (80 conexiones a 8080), descarga ANOMALO grande, tráfico normal que no dispara nada,
   flujo al revés y un incidente que se actualiza sin duplicarse. Además, `python -m pytest` en PC1 (69
   pruebas actuales) y en PC2 (110), todo en verde.
2. Reproducir las reglas sobre la sesión real guardada. Lo esperado: un incidente de `rafaga_conexiones`
   donde están las 2771 conexiones de la ráfaga, `transferencia_masiva` en las descargas grandes y 0
   incidentes en las descargas pequeñas y el ping. Si no sale así, se ajustan los umbrales con los datos.
3. Extremo a extremo en loopback: `servidor_demo.py` + `capturar_en_vivo.py` + la opción 5 de PC2
   apuntando a 127.0.0.1 (y nmap si está instalado), comprobando `incidentes.csv`.
4. `AppTest` del panel sin excepciones con incidentes presentes.
5. Entrenar el Random Forest y comprobar que se generan las métricas y la matriz.
