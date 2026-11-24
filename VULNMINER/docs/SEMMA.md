# SEMMA: ejecución y resultados

## Sample

`scripts/build_dataset.py` combina OWASP Benchmark Java 1.2, muestras únicas del CSV docente y casos controlados sintéticos. Conserva procedencia, CWE, lenguaje y etiquetas. No altera los originales. Salida: `data/vulnerabilities.csv`.

## Explore

```powershell
python scripts/explore.py
```

Produce `reports/exploration.json` y gráficos de clase, categorías OWASP con soporte público y lenguaje. En este material, el Benchmark aporta cinco categorías OWASP con soporte no sintético (A01/A02/A04/A05/A08); API8 tiene 36 casos públicos; las demás etiquetas se apoyan únicamente en sintéticos.

## Modify

El pipeline conserva identificadores y operadores mediante TF-IDF de palabras (unigramas y bigramas) y n-gramas de caracteres, más señales estáticas binarias de entradas, sinks, parámetros, autenticación, rutas, recursos, manejo de errores, dependencias y logging. Esas señales son variables de entrada; el modelo aprende sus pesos y las etiquetas. Separar la extracción de evidencia por línea permite explicar una señal sin sustituir la clasificación supervisada por reglas.

## Model

`scripts/train.py` compara Regresión Logística con Complement Naive Bayes para vulnerable/seguro. También ajusta clasificadores multietiqueta One-vs-Rest para etiquetas OWASP y API. El modelo seleccionado y los pipelines se serializan en `models/vulnminer.joblib`.

## Assess

El 20% de los casos Benchmark se reserva antes de agregar filas docentes/sintéticas; el split es estratificado y de `random_state=42`. Métricas: precisión, recall, F1 macro y por clase, matriz de confusión, multietiqueta micro/macro y exact match. Salidas: `reports/assessment.json`, `reports/classification_errors.csv`, `reports/owasp_metrics.csv`.

### Resultado registrado

En la ejecución incluida, se reservaron 70%/15%/15% de casos públicos para train/validation/test (1.915/410/411). Regresión Logística fue seleccionada con validation (F1 macro 0.9486 frente a 0.7206 de Complement Naive Bayes). En test obtuvo accuracy 0.9586, F1 macro 0.9586, precision vulnerable 0.9579 y recall vulnerable 0.9624. La matriz (filas reales seguro/vulnerable, columnas predichas seguro/vulnerable) fue `[[189,9],[8,205]]`.

El clasificador multietiqueta alcanzó métricas perfectas sobre las cinco clases OWASP presentes en el test (A01, A02, A04, A05 y A08) y API8, pero las etiquetas se derivan directamente del CWE del mismo Benchmark y sus casos comparten plantillas/familias entre particiones. Es un posible artefacto de distribución y no debe interpretarse como generalización ni eficacia real. API pública test solo contiene API8 (7 positivos); las demás API se entrenaron con ejemplos sintéticos, por lo que no tienen evaluación independiente.

El archivo `notebooks/SEMMA.ipynb` ofrece una vista ejecutable de estas cinco fases y carga las tablas/artefactos generados.
