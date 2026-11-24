# SEMMA: ejecución, ajuste de hiperparámetros y resultados

## 1. Sample

`scripts/build_dataset.py` integra tres fuentes públicas etiquetadas con CWE (**OWASP Benchmark Java 1.2**, **OWASP Benchmark Python 0.1** y el corpus público de casos de prueba **Semgrep Community Rules** — sin ejecutar el motor Semgrep), más las 10 muestras deduplicadas del docente y 9 pares controlados de configuración (`synthetic=true`). Conserva procedencia, CWE, lenguaje y `split_group`. Salida: `data/vulnerabilities.csv` (7.221 registros únicos: 3.915 vulnerables y 3.306 seguros; 0 duplicados exactos).

## 2. Explore

```bash
python scripts/explore.py
```

Produce `reports/exploration.json` y gráficos exploratorios en `reports/`. El corpus público cubre Java (3.395), Python (2.757), JavaScript (704), Configuration (259) y TypeScript (87).

## 3. Modify

`src/vulnminer/features.py` construye una representación numérica combinando:
- **TF-IDF de palabras** (unigramas y bigramas preservando operadores y símbolos de código, `max_features=60000`, `sublinear_tf=True`).
- **TF-IDF de n-gramas de caracteres** (`ngram_range=(3, 5)`, `max_features=50000`, `sublinear_tf=True`).
- **22 señales estáticas binarias** + `line_count` + `has_http_endpoint` (consultas SQL, parametrización, sinks HTML/shell/path, criptografía débil/fuerte, deserialización, debug/CORS/Docker root, solicitudes salientes, TLS inseguro, secretos embebidos, autorización, límites de recursos, asignación masiva, manejo de excepciones, dependencias y logging).

Las señales actúan exclusivamente como variables de entrada del modelo supervisado; los pesos y las categorías se aprenden a partir de los datos. El desbalance de clases se aborda mediante `class_weight="balanced"` (o `balanced_subsample` en Random Forest).

## 4. Model (comparación experimental y ajuste de hiperparámetros)

`scripts/train.py` divide los 7.202 registros públicos en **70% entrenamiento (5.060) / 15% validación (1.096) / 15% prueba (1.046)** mediante partición estratificada y agrupada por `split_group` (`random_state=42`, cero fuga de archivos entre particiones). Las muestras docentes y sintéticas se agregan exclusivamente a entrenamiento.

Todas las pruebas de validación quedan registradas en `reports/model_comparison.csv` (38 configuraciones evaluadas).

### Clasificación binaria (`vulnerable` vs `safe`) — Validación

Criterio de selección: mayor **F1 macro** en validación, con desempate por **recall vulnerable** (priorizando no omitir vulnerabilidades reales).

| Algoritmo | Mejores hiperparámetros | Accuracy | Precision macro | Recall macro | F1 macro | Recall vulnerable | Seleccionado |
|---|---|---:|---:|---:|---:|---:|:---:|
| **Logistic Regression** | `C=4.0`, `class_weight='balanced'` | **0.8668** | **0.8651** | **0.8664** | **0.8657** | 0.8706 | **Sí** |
| Random Forest | `n_estimators=150`, `max_depth=40`, `min_samples_leaf=2` | 0.8595 | 0.8643 | 0.8529 | 0.8562 | 0.9187 | No |
| Linear SVM (calibrado) | `C=2.0`, `class_weight='balanced'`, Platt `cv=3` | 0.7874 | 0.8143 | 0.7709 | 0.7742 | 0.9353 | No |
| Complement Naive Bayes | `alpha=0.1` | 0.7117 | 0.7101 | 0.7036 | 0.7049 | 0.7844 | No |

### Clasificación multietiqueta OWASP Top 10:2025 (6 categorías evaluadas) — Validación

Criterio de selección: mayor **F1 macro activo** en validación con ajuste conjunto de hiperparámetros y umbral (`0.30`–`0.55`).

| Algoritmo | Mejores hiperparámetros | Umbral | F1 macro activo | F1 micro | Exact Match | Seleccionado |
|---|---|---:|---:|---:|---:|:---:|
| **OvR Logistic Regression** | `C=4.0`, `class_weight='balanced'` | **0.40** | **0.8260** | **0.8911** | **0.8607** | **Sí** |
| OvR Linear SVM (calibrado) | `C=2.0`, `class_weight='balanced'` | 0.40 | 0.8166 | 0.8898 | 0.8491 | No |
| OvR Complement NB | `alpha=0.1` | 0.55 | 0.6338 | 0.7523 | 0.6584 | No |

### Clasificación multietiqueta OWASP API Security Top 10:2023 (5 categorías evaluadas) — Validación

| Algoritmo | Mejores hiperparámetros | Umbral | F1 macro activo | F1 micro | Exact Match | Seleccionado |
|---|---|---:|---:|---:|---:|:---:|
| **OvR Logistic Regression** | `C=1.0`, `class_weight='balanced'` | **0.45** | **0.4937** | **0.6980** | **0.9254** | **Sí** |
| OvR Linear SVM (calibrado) | `C=2.0`, `class_weight='balanced'` | 0.40 | 0.4457 | 0.6667 | 0.9171 | No |
| OvR Complement NB | `alpha=1.0` | 0.45 | 0.2162 | 0.2814 | 0.8391 | No |

Los modelos ganadores y sus pipelines de transformación se reentrenan con `train + validation` y se serializan en `models/vulnminer.joblib`.

## 5. Assess

### Desempeño binario (Train vs Validación vs Prueba independiente)

| Partición | Registros públicos | Accuracy | Precision macro | Recall macro | F1 macro | Recall vulnerable | Matriz `[safe, vuln]` |
|---|---:|---:|---:|---:|---:|---:|---|
| Entrenamiento (`train+val`) | 6.156 | 0.9672 | 0.9669 | 0.9671 | 0.9670 | 0.9682 | `[[2730, 96], [106, 3224]]` |
| Validación (selección) | 1.096 | 0.8668 | 0.8651 | 0.8664 | 0.8657 | 0.8706 | `[[425, 68], [78, 525]]` |
| **Prueba independiente** | **1.046** | **0.8815** | **0.8812** | **0.8794** | **0.8802** | **0.9018** | `[[408, 68], [56, 514]]` |

La brecha entre entrenamiento (`0.9670`) y prueba (`0.8802`) refleja una generalización razonable sin sobreajuste severo, y prueba supera ligeramente a validación al entrenar el modelo final con el 85% de los datos públicos.

### Desempeño multietiqueta en prueba independiente (`reports/owasp_metrics.csv`)

- **OWASP Top 10:2025 (6 evaluadas):** F1 micro `0.8852`, F1 macro activo `0.8002`, Exact Match `0.8596` (`A01: 0.7654`, `A02: 0.7391`, `A04: 0.9531`, `A05: 0.9184`, `A07: 0.6250`, `A08: 0.8000`). Declaradas **`no evaluada`**: `A03`, `A06`, `A09`, `A10`.
- **OWASP API Security Top 10:2023 (5 evaluadas):** F1 micro `0.6349`, F1 macro activo `0.5685`, Exact Match `0.9246` (`API2: 0.6250`, `API3: 0.1176`, `API7: 0.6000`, `API8: 0.8333`, `API10: 0.6667`). Declaradas **`no evaluada`**: `API1`, `API4`, `API5`, `API6`, `API9`.

Las salidas completas se guardan en `reports/assessment.json`, `reports/model_comparison.csv`, `reports/owasp_metrics.csv` y `reports/classification_errors.csv`.
