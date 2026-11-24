# Correspondencias CWE–OWASP usadas

La tabla del código `src/vulnminer/catalog.py` contiene correspondencias documentadas y orientativas entre debilidades CWE y categorías de **OWASP Top 10:2025** y **OWASP API Security Top 10:2023**. No constituye una tabla normativa exhaustiva; cada mapeo debe interpretarse junto con el contexto del microservicio y las referencias oficiales.

| CWE | OWASP Top 10:2025 | OWASP API Security Top 10:2023 | Alcance / Notas |
|---:|---|---|---|
| 22, 23, 36 | A01:2025 Broken Access Control | — | Path traversal / acceso a rutas fuera del directorio permitido. |
| 269, 276, 732 | A01:2025 Broken Access Control | API8:2023 (CWE-732) | Privilegios y permisos inseguros por defecto o incorrectos. |
| 352 | A01:2025 Broken Access Control | — | Cross-Site Request Forgery (CSRF). |
| 601 | A01:2025 Broken Access Control | — | Redirección abierta (Open Redirect). |
| 639 | A01:2025 Broken Access Control | API1:2023 BOLA | Control de acceso a objetos (requiere contexto de autorización). |
| 862, 863 | A01:2025 Broken Access Control | API1:2023 / API5:2023 | Autorización faltante o incorrecta sobre objetos/funciones. |
| 915, 1321 | A01:2025 Broken Access Control (CWE-915) | API3:2023 BOPLA | Asignación masiva / modificación de propiedades no autorizadas. |
| 918 | A01:2025 Broken Access Control | API7:2023 SSRF | En OWASP Top 10:2025, SSRF se consolida bajo A01. |
| 16, 489, 614, 942, 1004, 1275 | A02:2025 Security Misconfiguration | API8:2023 Security Misconfiguration | Debug activo, CORS permisivo, cookies sin Secure/HttpOnly/SameSite. |
| 250 | A02:2025 Security Misconfiguration | API8:2023 Security Misconfiguration | Ejecución con privilegios innecesarios (p. ej. `USER root` en Dockerfile). |
| 200 | A02:2025 Security Misconfiguration | API3:2023 BOPLA | Exposición excesiva de información sensible en respuestas/datos. |
| 829, 1357 | A03:2025 Software Supply Chain Failures | — | Inclusión de componentes externos no confiables. |
| 295 | A04:2025 Cryptographic Failures | API10:2023 Unsafe Consumption of APIs | Validación de certificados TLS deshabilitada en llamadas salientes. |
| 319, 326, 327, 328, 330 | A04:2025 Cryptographic Failures | — | Transmisión en texto claro, cifrado/hash débil o aleatoriedad insegura. |
| 78, 79, 89, 90, 91, 94, 95, 96, 113, 116, 611, 643, 943, 1336 | A05:2025 Injection | — | Inyección SQL, OS Command, XSS, Code/Eval, LDAP, XXE, XPath, NoSQL, SSTI. |
| 841 | A06:2025 Insecure Design | API6:2023 Sensitive Business Flows | Flujos de negocio sensibles; requiere análisis de diseño/lógica. |
| 287, 306, 347, 521, 522, 798 | A07:2025 Authentication Failures | API2:2023 Broken Authentication | Autenticación rota, verificación JWT ausente, credenciales embebidas. |
| 345, 353, 444 | A08:2025 Software or Data Integrity Failures | API10:2023 Unsafe Consumption of APIs (345, 444) | Verificación insuficiente de autenticidad/integridad de datos externos. |
| 501, 502 | A08:2025 Software or Data Integrity Failures | — | Violación de frontera de confianza y deserialización insegura. |
| 778 | A09:2025 Security Logging and Alerting Failures | — | Registro insuficiente de eventos de seguridad. |
| 209, 703 | A10:2025 Mishandling of Exceptional Conditions | — | Exposición de errores o manejo inadecuado de excepciones. |
| 400, 770, 1333 | A10:2025 (CWE-770) | API4:2023 Unrestricted Resource Consumption | Consumo irrestricto de recursos y expresiones regulares vulnerables (ReDoS). |
| 1059 | — | API9:2023 Improper Inventory Management | Requiere inventario real de versiones y endpoints desplegados. |

## Política de categorías `no evaluadas`

Solo se entrenan y evalúan las categorías que alcanzan un soporte público no sintético suficiente (`>= 15` registros en entrenamiento y `>= 3` en prueba independiente). Las categorías por debajo de ese umbral se declaran explícitamente como **`no evaluada`** en `reports/assessment.json`, `reports/owasp_metrics.csv` y los reportes generados por la CLI, evitando asignaciones arbitrarias.
