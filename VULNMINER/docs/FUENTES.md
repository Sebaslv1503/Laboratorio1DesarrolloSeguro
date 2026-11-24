# Fuentes y muestreo

## OWASP Benchmark Java 1.2

- Repositorio: <https://github.com/OWASP-Benchmark/BenchmarkJava>
- Commit fijado para esta extracción: `10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17`
- Etiquetas: `expectedresults-1.2.csv`, con nombre de caso, familia, condición vulnerable y CWE.
- Código: `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest*.java`.
- Se extrajeron los archivos disponibles y se normalizaron los identificadores de caso, las rutas que revelaban la categoría y comentarios. Se conservaron 2.736 de los 2.740 resultados esperados, tras omitir los cuatro casos cuyo archivo no estaba presente en la revisión descargada.
- Fuente destinada a evaluar detectores de seguridad, no a representar la distribución de fallos de un producto real. El conjunto tiene familias de CWE repetidas y plantillas similares.
- Licencia upstream GNU GPL v2; véase `data/licenses/OWASP_Benchmark_LICENSE` y el archivo `LICENSE` del repositorio upstream.

## Dataset del docente

`referencia-profesor/code_vulnerabilities.csv` tiene 1.000 filas originales, cuatro columnas (`Code Snippet`, `Vulnerability Type`, `Location`, `Preprocessed Tokens`), clases SQLi/XSS, diez fragmentos exactos y ningún ejemplo seguro. Se usaron las diez muestras únicas, etiquetadas como vulnerables, sin alterar el archivo fuente. No aportan un test independiente.

## Casos controlados sintéticos

70 fragmentos escritos para cubrir CWE/API sin representación pública suficiente en las fuentes anteriores: 54 vulnerables y 16 seguros. La columna `provenance=synthetic-controlled` y `synthetic=true` los distingue. Se incluyen en entrenamiento únicamente; quedan excluidos del test del Benchmark. Son ejemplos didácticos diseñados por patrón, no hallazgos observados, y su reutilización para evaluación daría resultados inflados.

## Distribución actual

Revisar `reports/exploration.json` para conteos reproducibles. El dataset final tiene 2.816 filas, 1.479 vulnerables y 1.337 seguras; 2.746 no sintéticas y 70 sintéticas. Hay 2.736 casos Benchmark, diez muestras únicas del docente, Java principalmente y unos pocos fragmentos Python/JavaScript.

## Muestreo y partición

Las filas se deduplicaron por código, etiqueta y CWE. Se parte el Benchmark Java en 70%/15%/15% estratificado por etiqueta, usando `random_state=42`; validation selecciona el algoritmo, test queda intacto y el dataset docente/sintético solo se agrega a entrenamiento. El test contiene archivos no vistos durante el ajuste, pero el mismo proyecto Benchmark y familias CWE representadas en train. Es una prueba interna del benchmark, no una validación sobre un microservicio independiente ni evidencia de despliegue.
