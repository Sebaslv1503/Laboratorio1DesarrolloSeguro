# Diccionario de datos (`data/vulnerabilities.csv`)

| Campo | Tipo | Significado |
|---|---|---|
| `record_id` | texto | Identificador SHA-256 truncado derivado del código normalizado, CWE principal y etiqueta. |
| `code` | texto | Fragmento de código fuente o archivo de configuración limpio (sin comentarios de anotación). |
| `language` | texto | Lenguaje o tipo de archivo: `Java`, `Python`, `JavaScript`, `TypeScript` o `Configuration`. |
| `label` | categoría | `vulnerable` o `safe`, según la fuente original. |
| `cwe` | entero/texto | Identificador CWE principal asociado al caso. |
| `owasp_categories` | lista separada por `;` | Categorías OWASP Top 10:2025 derivadas de la tabla documentada CWE–OWASP (`docs/CWE_OWASP.md`). Vacío para `safe`. |
| `api_categories` | lista separada por `;` | Categorías OWASP API Security Top 10:2023 derivadas de la tabla documentada. Vacío si no aplica o para `safe`. |
| `provenance` | texto | Fuente de origen: `OWASP Benchmark Java 1.2`, `OWASP Benchmark Python 0.1`, `Semgrep Community Rules`, `Dataset profesor (muestra deduplicada)` o `synthetic-controlled`. |
| `source_id` | texto | Identificador trazable del archivo y línea o caso upstream. |
| `split_group` | texto | Clave de agrupación por archivo de caso/regla para garantizar particiones train/validation/test sin fuga de información. |
| `synthetic` | booleano | Indica si el ejemplo fue redactado como caso controlado (`true`: solo se usa en entrenamiento, nunca en prueba). |

Las correspondencias CWE–OWASP son orientativas y documentadas; una misma debilidad CWE puede corresponder simultáneamente a ambos estándares OWASP.
