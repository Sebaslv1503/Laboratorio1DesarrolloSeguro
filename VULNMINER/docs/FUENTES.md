# Fuentes y muestreo

El conjunto de datos (`data/vulnerabilities.csv`) integra múltiples repositorios públicos etiquetados con CWE para cubrir varios lenguajes de programación (Java, Python, JavaScript, TypeScript) y archivos de configuración, además de ejemplos controlados trazables. **No se ejecuta ninguna herramienta SAST externa ni LLM en el flujo de clasificación.**

## 1. OWASP Benchmark Java 1.2

- **Repositorio:** <https://github.com/OWASP-Benchmark/BenchmarkJava>
- **Commit fijado:** `10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17`
- **Etiquetas:** `expectedresults-1.2.csv` (caso, categoría, vulnerabilidad real y CWE).
- **Código:** `src/main/java/org/owasp/benchmark/testcode/BenchmarkTest*.java` (2.736 archivos conservados).
- **Limpieza:** se normalizaron los identificadores `BenchmarkTest*`, rutas que revelaban la categoría (`/sqli-00/`, etc.), `package` y comentarios.
- **Licencia:** GNU GPL v2 (`data/licenses/OWASP_Benchmark_LICENSE`).

## 2. OWASP Benchmark Python 0.1

- **Repositorio:** <https://github.com/OWASP-Benchmark/BenchmarkPython>
- **Commit fijado:** `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`
- **Etiquetas:** `expectedresults-0.1.csv` (1.230 archivos Python etiquetados como vulnerables o seguros con su CWE).
- **Código:** `testcode/BenchmarkTest*.py`.
- **Limpieza:** se eliminaron cabeceras de licencia, comentarios, nombres `BenchmarkTest*` y segmentos de ruta que pudieran filtrar la categoría.
- **Licencia:** GNU GPL v3 (`data/licenses/OWASP_BenchmarkPython_LICENSE`).

## 3. Repositorio público de casos de prueba con CWE (`semgrep/semgrep-rules`)

- **Repositorio:** <https://github.com/semgrep/semgrep-rules>
- **Commit fijado:** `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2`
- **Uso estricto:** utilizado **exclusivamente como corpus público de fragmentos de código fuente etiquetados con CWE** (archivos de prueba comunitarios en Python, JavaScript, TypeScript, Java, Dockerfile, YAML, `.properties` y XML). El motor Semgrep **no se instala ni se ejecuta** en ninguna etapa del proyecto.
- **Extracción y limpieza:** a partir de los metadatos CWE de cada archivo `.yaml` y los bloques anotados (`ruleid:` → vulnerable, `ok:` → seguro) en su archivo de prueba asociado, se extrajeron ventanas de código limpias eliminando por completo todos los comentarios de anotación para evitar filtración de etiquetas. Cada archivo de regla conforma un `split_group` único.
- **Aporte:** 3.236 registros únicos deduplicados en Python, Java, JavaScript, TypeScript y Configuración.
- **Licencia:** Semgrep Rules License v1.0 (`data/licenses/Semgrep_Rules_LICENSE`).

## 4. Dataset del docente (muestra deduplicada)

- `referencia-profesor/code_vulnerabilities.csv` contenía 1.000 filas reducibles a 10 fragmentos exactos únicos (5 SQLi en Python, 5 XSS en JavaScript, sin clase segura).
- Se incorporan únicamente las 10 muestras únicas deduplicadas exclusivamente en el conjunto de entrenamiento (`provenance=Dataset profesor (muestra deduplicada)`).

## 5. Casos controlados de configuración (`synthetic-controlled`)

- 9 pares controlados (5 vulnerables, 4 seguros) de archivos `application.yml`, `application.properties` y `docker-compose.yml` con `synthetic=true`.
- Se usan únicamente en entrenamiento y quedan **excluidos del conjunto de prueba independiente**.

## Distribución actual (verificada en `reports/exploration.json`)

- **Total deduplicado:** 7.221 registros (`3.915` vulnerables, `3.306` seguros; `0` duplicados exactos por `code`/`label`/`cwe`).
- **Por fuente:**
  - `Semgrep Community Rules`: 3.236
  - `OWASP Benchmark Java 1.2`: 2.736
  - `OWASP Benchmark Python 0.1`: 1.230
  - `Dataset profesor (muestra deduplicada)`: 10
  - `synthetic-controlled`: 9
- **Por lenguaje:**
  - `Java`: 3.395
  - `Python`: 2.762
  - `JavaScript`: 709
  - `Configuration`: 268
  - `TypeScript`: 87

## Procedimiento de muestreo y partición

1. Todos los registros se deduplican por `(code, label, cwe)`.
2. Los 7.202 registros de fuentes públicas (`OWASP Benchmark Java 1.2`, `OWASP Benchmark Python 0.1` y `Semgrep Community Rules`) se dividen en **70% entrenamiento (5.060) / 15% validación (1.096) / 15% prueba (1.046)** mediante partición estratificada por `(fuente, lenguaje, categoría)` y **agrupada por `split_group`**, garantizando cero solapamiento de archivos de prueba/regla entre particiones (`random_state=42`).
3. Las 10 muestras del docente y los 9 casos controlados de configuración se agregan exclusivamente a entrenamiento; la validación y la prueba contienen únicamente datos públicos no vistos.
4. Solo se entrenan y evalúan categorías con soporte público suficiente (`>= 15` en entrenamiento público y `>= 3` en prueba pública): **6 categorías de OWASP Top 10:2025** (`A01, A02, A04, A05, A07, A08`) y **5 categorías de OWASP API Security Top 10:2023** (`API2, API3, API7, API8, API10`). Las 9 categorías restantes se declaran explícitamente como **`no evaluada`**.

## Limitaciones de las fuentes

- Los benchmarks OWASP y los archivos de prueba de `semgrep-rules` consisten en casos curados más cortos y regulares que repositorios productivos completos; por ello la evaluación sobre proyectos de microservicios externos sigue siendo indispensable.
- TypeScript (87 registros en total, 3 en prueba) y Configuration (268 en total, 31 en prueba) tienen menor volumen que Java/Python.
- Categorías dependientes de autorización por objeto/función (`API1`, `API5`), lógica de negocio (`A06`, `API6`), inventario (`API9`), cadena de suministro (`A03`), logging (`A09`), condiciones excepcionales (`A10`) o límites de consumo (`API4`) quedan declaradas como `no evaluada` al no contar con soporte público suficiente en prueba.
