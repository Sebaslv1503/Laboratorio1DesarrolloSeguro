# Diccionario de datos (`data/vulnerabilities.csv`)

| Campo | Tipo | Significado |
|---|---|---|
| `record_id` | texto | Identificador derivado del contenido normalizado, CWE y etiqueta. |
| `code` | texto | Código o configuración de muestra. |
| `language` | texto | Lenguaje reconocido o `mixed` para casos sintéticos controlados. |
| `label` | categoría | `vulnerable` o `safe`, según Benchmark, docente o etiqueta manual explícita. |
| `cwe` | entero/texto | Identificador CWE asociado; en ejemplos seguros conserva la familia de control comparada. |
| `owasp_categories` | lista separada por `;` | Categorías candidatas OWASP Top 10:2025 derivadas de la tabla orientativa CWE-OWASP. Vacío para `safe`. |
| `api_categories` | lista separada por `;` | Categorías candidatas API Security Top 10:2023 derivadas de la tabla orientativa. Vacío si no hay mapeo. |
| `provenance` | texto | `OWASP Benchmark Java 1.2`, `Dataset profesor (muestra deduplicada)` o `synthetic-controlled`. |
| `source_id` | texto | Nombre del caso upstream o identificador de muestra sintética/docente. |
| `split_group` | texto | Grupo/fuente para auditoría de particiones; la separación actual reserva archivos Benchmark completos. |
| `synthetic` | booleano | Indica si el fragmento fue escrito como control sintético. |

No se interpretan los mapeos CWE-OWASP como relación oficial única. Una CWE puede asociarse a más de una categoría según contexto y versión del estándar.
