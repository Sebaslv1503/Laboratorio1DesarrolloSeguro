# Correspondencias CWE–OWASP usadas

La tabla del código `src/vulnminer/catalog.py` contiene mapeos educativos para etiquetas de entrenamiento, no una tabla de equivalencia exhaustiva o normativa. El docente debe validar cada mapeo con el contexto del caso y las referencias oficiales.

| CWE | OWASP Top 10:2025 sugerido | OWASP API:2023 sugerido | Alcance |
|---:|---|---|---|
| 22, 23, 36 | A01 Broken Access Control | — | Traversal puede ser control de acceso/contexto. |
| 639 | A01 Broken Access Control | API1 BOLA | Control de acceso a objetos. |
| 862, 863 | A01 Broken Access Control | API1/API5 | Autorización faltante o incorrecta. |
| 915 | A01 Broken Access Control | API3 BOPLA | Asignación/propiedad debe revisarse por contexto. |
| 16, 614 | A02 Security Misconfiguration | API8 Security Misconfiguration | Configuración expuesta o cookie insegura. |
| 829 | A03 Software Supply Chain Failures | — | Componente externo no confiable. |
| 327, 328, 330 | A04 Cryptographic Failures | — | Primitiva débil o aleatoria insegura. |
| 78, 79, 89, 90, 91, 94, 113, 611, 643 | A05 Injection | — | Diferentes formas de inyección y neutralización. |
| 841 | A06 Insecure Design | API6 Sensitive Business Flows | El flujo requiere entender reglas de negocio. |
| 287, 306, 798 | A07 Authentication Failures | API2 Broken Authentication | Autenticación/credenciales. |
| 501, 502 | A08 Software or Data Integrity Failures | — | Límite de confianza/deserialización. |
| 778 | A09 Security Logging and Alerting Failures | API9 solo con contexto de inventario | Registro insuficiente; API9 no se infiere de CWE-778. |
| 209, 703, 770 | A10 Mishandling Exceptional Conditions | API4 para límites de consumo | Error, fallo abierto o consumo excesivo. |
| 918 | A01 en Top 10:2025 | API7 SSRF | OWASP 2025 incorporó SSRF dentro de A01. |
| 1059 | — | API9 Improper Inventory Management | Requiere inventario de endpoints/versiones real. |
| 345, 444 | A08 sugerido | API10 Unsafe Consumption of APIs | Revisión del consumo de respuesta de terceros. |

La evidencia pública del Benchmark no cubre la mayoría de riesgos de API. Los casos API añadidos están marcados como sintéticos en el CSV y se usan para que el pipeline ejercite estas etiquetas; no demuestran precisión de API.
