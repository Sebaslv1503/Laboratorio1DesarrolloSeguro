# VULNMINER

Primera versión académica de una CLI que analiza código y configuraciones de proyectos pequeños de microservicios. Clasifica candidatos con modelos supervisados (TF-IDF de palabras y caracteres, señales de código aprendidas y regresión logística) y añade evidencia por línea mediante señales estáticas complementarias. No usa LLM.

## Entorno e instalación

Desde esta carpeta, active el `.venv` existente en la carpeta padre y ejecute:

```powershell
..\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

La CLI carga `models/vulnminer.joblib`; no entrena durante el escaneo. Para reproducir SEMMA desde `data/vulnerabilities.csv`:

```powershell
python scripts/explore.py
python scripts/train.py
```

La preparación completa del dataset necesita una copia local de [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) y, opcionalmente, el CSV del docente:

```powershell
python scripts/build_dataset.py --benchmark-root C:\ruta\BenchmarkJava --teacher-csv ..\referencia-profesor\code_vulnerabilities.csv
```

## Escaneo

```powershell
vulnminer scan . --standards owasp2025,api2023 --format json,html --output .\reportes
python -m vulnminer scan . --standards owasp2025,api2023 --format json,html --output .\reportes
```

Soporta Java, Python, JavaScript y TypeScript, además de Dockerfile, YAML, TOML, JSON, XML, `.properties`, `.env` y archivos comunes de dependencias. Los reportes incluyen servicio, archivo, línea, evidencia, CWE orientativo, categorías, confianza, estimación de severidad separada de la confianza y recomendación.

## Resultados de la evaluación incluida

`reports/assessment.json` registra la comparación de Regresión Logística y Complement Naive Bayes sobre un 20% reservado del OWASP Benchmark Java 1.2. La división separa archivos, pero proviene del mismo proyecto/benchmark y no demuestra generalización a repositorios externos. Los ejemplos sintéticos se usan solo para entrenar etiquetas sin datos públicos suficientes; no entran en la prueba independiente. Los mapeos CWE-OWASP son aproximaciones educativas y requieren revisión.

## Límites conocidos

- El Benchmark usado contiene Java; el CSV docente aporta solo diez fragmentos únicos vulnerables de SQLi/XSS. Los datos sintéticos amplían etiquetas y lenguajes de forma transparente.
- OWASP Top 10:2025 tiene evidencia pública en cinco categorías (A01, A02, A04, A05, A08). OWASP API Security 2023 tiene evidencia pública en API8 solamente. El resto de etiquetas se entrenó con casos controlados sintéticos; no debe leerse como cobertura validada.
- Acceso a objetos, lógica de negocio, inventario y falta de controles suelen necesitar contexto de ejecución o revisión humana. Los hallazgos son potenciales, nunca confirmaciones.
- La confianza no es severidad. No se calcula CVSS.
- El clasificador mira el contenido textual de archivos completos; no resuelve flujos de datos ni contexto entre servicios. No es sustituto de auditoría, pruebas dinámicas ni revisión experta.

Consulte [docs/SEMMA.md](docs/SEMMA.md), [docs/FUENTES.md](docs/FUENTES.md), [docs/DICCIONARIO.md](docs/DICCIONARIO.md), [docs/CWE_OWASP.md](docs/CWE_OWASP.md) y [docs/ARQUITECTURA.md](docs/ARQUITECTURA.md).
