# Revisión del material docente y brechas

## Documento oficial del laboratorio

El PDF solicita clasificación para OWASP Top 10:2025 y OWASP API Security 2023, SEMMA, al menos 500 ejemplos con 100 seguros, comparación de dos modelos, métricas por clase, modelo serializado, dos lenguajes, descubrimiento de microservicios y reportes JSON/HTML. Recomienda 70/15/15 y pide evidencia para cinco categorías OWASP y cuatro API; categoriza la salida como posible hallazgo sujeto a revisión. Se incorpora la cautela de que confianza no equivale a severidad y se mantiene la prohibición de LLM.

## Notebook Taller 01

Implementa clasificación binaria con TF-IDF de unigramas/bigramas y Regresión Logística, split estratificado 75/25, accuracy, precision/recall/F1, matriz de confusión, errores y explicabilidad LIME. Puede descargar el dataset de Kaggle, pero si solo existe una clase genera controles seguros/vulnerables sintéticos. La evaluación es de fragmentos y no separa por repositorio.

**Reutilizado:** baseline textual supervisado, tratamiento de tokenización de código, métricas con foco en recall vulnerable, análisis de falsos positivos/negativos y el concepto de explicación local.

**Ampliación:** el muestreo actual combina código de OWASP Benchmark con etiquetas/CWE, reserva train/validation/test y agrega información de procedencia; el clasificador considera caracteres y señales estáticas aprendidas y se integra en una CLI.

## Notebook Taller 02

Construye aproximadamente 800 filas desde plantillas para diez categorías OWASP Top 10:2021, con mutaciones simples, tokens y comentarios; usa TF-IDF (1,2), Regresión Logística y Random Forest de 300 árboles. Compara en un split aleatorio, elige por accuracy, produce matriz de confusión y explicaciones SHAP/LIME. No usa fragmentos de un conjunto real para esas categorías y su clasificación corresponde a OWASP 2021, no al estándar actual de este laboratorio.

**Reutilizado:** EDA por categoría, TF-IDF que conserva símbolos de código, comparación de clasificadores clásicos, confusión y análisis crítico de artefactos sintéticos.

**No trasladado como evidencia:** las plantillas OWASP 2021 ni sus métricas no son equivalentes a datos públicos, a API Security 2023 ni a OWASP 2025. No se duplicó el generador de 800 registros sintéticos.

## Dataset del docente

El CSV tiene 1.000 filas y cuatro columnas: fragmento, tipo, ubicación y tokens preprocesados. Sin embargo, se reduce a diez fragmentos exactos distintos; solo tiene etiquetas `SQLi`/`XSS`, 500 filas por etiqueta, y ninguna clase segura. Mantener las 1.000 filas duplicaría los mismos textos y sesgaría el modelo. La muestra unificada conserva una copia de cada fragmento con procedencia docente y los originales siguen intactos.

## Actividades docentes

La primera actividad espera evaluación manual y LIME para diez fragmentos; la segunda explora un clasificador OWASP 2021 sintético y LIME/SHAP. Esos objetivos didácticos se mantienen en el análisis crítico de limitaciones, pero el alcance del PDF oficial de este proyecto es una CLI SEMMA para versiones 2025/2023; por eso el entregable se centra en datos trazables, entrenamiento reproducible, análisis de microservicios y reportes.

## Brechas aún abiertas

- No está disponible el proyecto desconocido que entregará el docente; la demostración local es un fixture sintético y no una validación externa independiente.
- El entrenamiento público casi no cubre API Security: solo API8 tiene casos públicos en el test. El resto se entrenó con controles sintéticos y no se afirma cobertura de precisión validada.
- El entrenamiento es casi totalmente Java. Python/JavaScript/TypeScript se reconocen en la CLI, pero requieren más datos etiquetados independientes para afirmar soporte de calidad comparable.
- Las relaciones CWE-OWASP son contextuales; la tabla usada es orientación curada y debe revisarse con el docente antes de presentarse como mapeo definitivo.
- Categorías de diseño, negocio, inventario, autorización y monitoreo necesitan contexto, pruebas dinámicas y revisión humana; análisis textual aislado no las confirma.
