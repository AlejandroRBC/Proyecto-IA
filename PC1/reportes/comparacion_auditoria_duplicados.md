# Auditoría de duplicados: métricas antes y después de la corrección

Generado: 2026-11-25T12:49:16. El modelo y el umbral son los mismos;
solo cambia qué filas de evaluación sobreviven a la deduplicación.

- **Antes:** duplicados por las 10 características (`keep="first"`). Una fila de ataque
  podía descartarse en favor de una benigna con los mismos valores.
- **Después:** duplicados por las 10 características + `Label`.

## Diagnóstico

| Concepto | Valor |
|---|---|
| Grupos duplicados (mismas 10 características) | 114,785 |
| Duplicado seguro (una sola etiqueta) | 113,275 |
| Duplicado conflictivo (más de una etiqueta) | 1,510 |
| Filas eliminadas en favor de una fila con otra etiqueta | 49,393 |
| Filas eliminadas con el criterio anterior | 481,983 |
| Filas eliminadas con el criterio corregido | 480,448 |

## Métricas generales

| Métrica | Antes | Después | Diferencia |
|---|---|---|---|
| Precision | 0.0073 | 0.0073 | 0.0000 |
| Recall | 0.0003 | 0.0003 | -0.0000 |
| F1 | 0.0006 | 0.0006 | -0.0000 |
| FPR | 1.22% | 1.22% | -0.00% |
| ROC-AUC | 0.6953 | 0.6946 | -0.0007 |
| Verdaderos positivos | 126 | 126 | +0 |
| Falsos positivos | 17,081 | 17,081 | +0 |
| Falsos negativos | 414,588 | 415,813 | +1,225 |
| Flujos evaluados | 1,816,412 | 1,817,947 | +1,535 |

## Proporción detectada por tipo de Label

En los ataques es el recall; en BENIGN es la tasa de falsos positivos. Los ataques de volumen van en **negrita**.

| Label | Flujos antes | Detección antes | Flujos después | Detección después | Diferencia |
|---|---|---|---|---|---|
| **PortScan** | 90,046 | 0.00% | 90,618 | 0.00% | +0.00 pp |
| **DDoS** | 127,172 | 0.00% | 127,186 | 0.00% | +0.00 pp |
| **DoS Hulk** | 165,864 | 0.00% | 166,334 | 0.00% | +0.00 pp |
| BENIGN | 1,401,698 | 1.22% | 1,402,008 | 1.22% | -0.00 pp |
| DoS GoldenEye | 10,259 | 0.00% | 10,281 | 0.00% | +0.00 pp |
| DoS Slowhttptest | 5,164 | 0.04% | 5,172 | 0.04% | -0.00 pp |
| DoS slowloris | 4,863 | 0.00% | 4,867 | 0.00% | +0.00 pp |
| FTP-Patator | 4,257 | 0.00% | 4,257 | 0.00% | +0.00 pp |
| SSH-Patator | 3,107 | 0.00% | 3,149 | 0.00% | +0.00 pp |
| Bot | 1,910 | 0.73% | 1,931 | 0.73% | -0.01 pp |
| Web Attack � Brute Force | 1,385 | 5.13% | 1,426 | 4.98% | -0.15 pp |
| Web Attack � XSS | 625 | 2.56% | 651 | 2.46% | -0.10 pp |
| Infiltration | 36 | 33.33% | 36 | 33.33% | +0.00 pp |
| Web Attack � Sql Injection | 15 | 0.00% | 20 | 0.00% | +0.00 pp |
| Heartbleed | 11 | 100.00% | 11 | 100.00% | +0.00 pp |

## Conclusión

El recall de los ataques de volumen (PortScan, DDoS, DoS Hulk) **sigue en 0 % después de la corrección**. El problema de deduplicación era real (1,510 grupos conflictivos), pero solo devolvió a la evaluación +572 filas de PortScan, +14 filas de DDoS, +470 filas de DoS Hulk. Casi todas esas filas tienen exactamente las mismas 10 características que alguna fila BENIGN, y el modelo solo ve esas características: les da el mismo puntaje que al tráfico normal. **El bug no explicaba el 0 %:** la limitación estructural de Isolation Forest con los ataques de volumen sigue siendo válida.

En términos globales, los verdaderos positivos pasan de 126 a 126 y el ROC-AUC de 0.6953 a 0.6946.
